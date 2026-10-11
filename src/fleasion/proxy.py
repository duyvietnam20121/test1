"""Proxy TLS tối giản: chỉ chặn ClientSettings của Roblox để ghép FastFlag.

Luồng: Roblox -> (hosts: 127.0.0.1:443) -> proxy này -> IP thật của Roblox.
Mỗi request được chuyển tiếp qua một kết nối upstream riêng (``Connection: close``),
phù hợp với các request ClientSettings nhỏ, ít gặp.
"""

from __future__ import annotations

import asyncio
import ipaddress
import random
import socket
import ssl
import struct
import threading
from collections.abc import Awaitable, Callable
from pathlib import Path

from .fflags import (
    FFlagModifier,
    compress_dcz,
    dcz_dictionary_sha256,
    decompress_body,
    decompress_dcz,
    dictionary_matches,
)
from .log import log_buffer

CLIENT_SETTINGS_HOSTS: frozenset[str] = frozenset(
    {'clientsettings.roblox.com', 'clientsettingscdn.roblox.com'}
)
DICTIONARY_HOST = 'clientsettings.roblox.com'

# Giới hạn TLS 1.2 phía cục bộ để tránh lỗi bắt tay do OpenSSL/middlebox trên Windows.
PROXY_TLS_MAX_VERSION = ssl.TLSVersion.TLSv1_2

DNS_FALLBACK_SERVERS = ('1.1.1.1', '8.8.8.8', '9.9.9.9')
MAX_BODY_BYTES = 64 * 1024 * 1024
MAX_HEADER_BYTES = 1024 * 1024
CLIENT_IDLE_TIMEOUT = 120.0
UPSTREAM_CONNECT_TIMEOUT = 10.0
UPSTREAM_IO_TIMEOUT = 30.0

Headers = list[tuple[str, str]]
Connector = Callable[[str], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]

_HOP_BY_HOP = {
    'connection',
    'keep-alive',
    'proxy-connection',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'upgrade',
    'transfer-encoding',
    'content-length',
}
_STALE_AFTER_MODIFY = {'etag', 'content-md5', 'x-signature-ed25519', 'content-encoding'}
_NO_BODY_STATUSES = {204, 304}


# ---------------------------------------------------------------------------
# DNS: tìm IP thật của Roblox (hosts đã trỏ tên miền về 127.0.0.1)
# ---------------------------------------------------------------------------


def _is_usable_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
        or address.is_reserved
    )


def _skip_dns_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + length


def dns_query_udp(host: str, server: str, *, timeout: float = 3.0, qtype: int = 1) -> list[str]:
    """Truy vấn UDP trực tiếp tới máy chủ DNS (bỏ qua file hosts). qtype 1=A, 28=AAAA."""
    query_id = random.randrange(0x10000)
    question = b''.join(
        bytes([len(label)]) + label for label in (p.encode('idna') for p in host.rstrip('.').split('.'))
    ) + b'\x00'
    packet = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack('>HH', qtype, 1)

    family = socket.AF_INET6 if ':' in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _addr = sock.recvfrom(4096)

    if len(data) < 12:
        return []
    response_id, flags, qdcount, ancount = struct.unpack('>HHHH', data[:8])
    if response_id != query_id or flags & 0x000F:
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset) + 4
    addresses: list[str] = []
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        rtype, _rclass, _ttl, rdlength = struct.unpack('>HHIH', data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == qtype == 1 and rdlength == 4:
            addresses.append(socket.inet_ntop(socket.AF_INET, rdata))
        elif rtype == qtype == 28 and rdlength == 16:
            addresses.append(socket.inet_ntop(socket.AF_INET6, rdata))
    return addresses


class UpstreamResolver:
    """Giữ danh sách IP thật cho từng tên miền bị chặn."""

    def __init__(self) -> None:
        self._endpoints: dict[str, list[str]] = {}
        self._lock = threading.Lock()

    def prime(self, hosts) -> None:
        """Phân giải bằng DNS của hệ điều hành. PHẢI gọi trước khi sửa file hosts."""
        for host in sorted(hosts):
            ips: list[str] = []
            try:
                for family, _t, _p, _c, sockaddr in socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM):
                    ip = sockaddr[0]
                    if family in (socket.AF_INET, socket.AF_INET6) and _is_usable_ip(ip) and ip not in ips:
                        ips.append(ip)
            except OSError as exc:
                log_buffer.log('Proxy', f'DNS hệ thống không phân giải được {host}: {exc}')
            if not ips:
                ips = self._public_dns(host)
            ips.sort(key=lambda ip: ':' in ip)  # IPv4 trước
            with self._lock:
                self._endpoints[host] = ips
            if ips:
                log_buffer.log('Proxy', f'{host} -> {ips[0]}')
            else:
                log_buffer.log('Proxy', f'Không tìm được IP thật của {host} (kiểm tra mạng/VPN/tường lửa)')

    def refresh(self, host: str) -> list[str]:
        """Phân giải lại qua DNS công cộng (hosts đã trỏ về loopback nên DNS hệ thống vô dụng)."""
        ips = self._public_dns(host)
        if ips:
            with self._lock:
                self._endpoints[host] = ips
        return ips

    def get(self, host: str) -> list[str]:
        with self._lock:
            return list(self._endpoints.get(host, []))

    @staticmethod
    def _public_dns(host: str) -> list[str]:
        for server in DNS_FALLBACK_SERVERS:
            ips: list[str] = []
            for qtype in (1, 28):
                try:
                    ips.extend(ip for ip in dns_query_udp(host, server, qtype=qtype) if _is_usable_ip(ip))
                except (OSError, struct.error, IndexError, UnicodeError):
                    continue
            if ips:
                return sorted(dict.fromkeys(ips), key=lambda ip: ':' in ip)
        return []


# ---------------------------------------------------------------------------
# HTTP/1.1 tối giản
# ---------------------------------------------------------------------------


def header_get(headers: Headers, name: str, default: str = '') -> str:
    lowered = name.lower()
    for key, value in headers:
        if key.lower() == lowered:
            return value
    return default


def _without(headers: Headers, names: set[str]) -> Headers:
    return [(k, v) for k, v in headers if k.lower() not in names]


async def read_head(reader: asyncio.StreamReader) -> tuple[str, Headers] | None:
    """Đọc dòng đầu + header. Trả về None nếu kết nối đóng trước khi có dữ liệu."""
    raw = bytearray()
    while True:
        line = await reader.readline()
        if not line:
            return None
        raw += line
        if line in (b'\r\n', b'\n'):
            break
        if len(raw) > MAX_HEADER_BYTES:
            raise ValueError('Header HTTP quá lớn')
    lines = bytes(raw).decode('latin-1').splitlines()
    while lines and not lines[0]:
        lines.pop(0)
    if not lines:
        return None
    headers: Headers = []
    for line in lines[1:]:
        if not line or ':' not in line:
            continue
        name, _, value = line.partition(':')
        headers.append((name.strip(), value.strip()))
    return lines[0], headers


async def read_body(
    reader: asyncio.StreamReader, headers: Headers, *, until_eof: bool = False
) -> bytes:
    """Đọc body theo Transfer-Encoding/Content-Length; ``until_eof`` cho response không có độ dài."""
    if 'chunked' in header_get(headers, 'transfer-encoding').lower():
        body = bytearray()
        while True:
            size_line = (await reader.readline()).split(b';', 1)[0].strip()
            if not size_line:
                raise asyncio.IncompleteReadError(bytes(body), None)
            size = int(size_line, 16)
            if size == 0:
                while (await reader.readline()) not in (b'\r\n', b'\n', b''):
                    pass
                return bytes(body)
            if len(body) + size > MAX_BODY_BYTES:
                raise ValueError('Body quá lớn')
            body += await reader.readexactly(size)
            await reader.readexactly(2)
    length_text = header_get(headers, 'content-length')
    if length_text:
        length = int(length_text)
        if length < 0 or length > MAX_BODY_BYTES:
            raise ValueError('Content-Length không hợp lệ')
        return await reader.readexactly(length) if length else b''
    if until_eof:
        data = await reader.read(MAX_BODY_BYTES + 1)
        if len(data) > MAX_BODY_BYTES:
            raise ValueError('Body quá lớn')
        return data
    return b''


def build_response(
    status_line: str,
    headers: Headers,
    body: bytes,
    *,
    keep_alive: bool,
    head_request: bool = False,
) -> bytes:
    status = int(status_line.split()[1])
    lines = [status_line]
    for key, value in _without(headers, _HOP_BY_HOP):
        lines.append(f'{key}: {value}')
    if head_request:
        length = header_get(headers, 'content-length')
        if length:
            lines.append(f'Content-Length: {length}')
        body = b''
    elif status not in _NO_BODY_STATUSES and not 100 <= status < 200:
        lines.append(f'Content-Length: {len(body)}')
    lines.append(f'Connection: {"keep-alive" if keep_alive else "close"}')
    return ('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1') + body


def simple_response(status: int, reason: str, message: str) -> bytes:
    body = message.encode('utf-8')
    return (
        f'HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n'
        f'Content-Length: {len(body)}\r\nConnection: close\r\n\r\n'
    ).encode('latin-1') + body


# ---------------------------------------------------------------------------
# Proxy
# ---------------------------------------------------------------------------


def _client_ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    try:
        import certifi

        context.load_verify_locations(certifi.where())
    except Exception:
        pass
    return context


class ClientSettingsProxy:
    """Máy chủ TLS cục bộ cho các tên miền ClientSettings."""

    def __init__(
        self,
        modifier: FFlagModifier,
        cert_path: Path,
        key_path: Path,
        resolver: UpstreamResolver,
        *,
        hosts: frozenset[str] = CLIENT_SETTINGS_HOSTS,
        listen_host: str = '127.0.0.1',
        listen_port: int = 443,
        connector: Connector | None = None,
        server_ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self.modifier = modifier
        self.hosts = frozenset(h.lower() for h in hosts)
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._resolver = resolver
        self._connector = connector or self._connect_upstream
        self._upstream_ctx = _client_ssl_context()
        self._dictionary_cache: dict[str, bytes] = {}

        if server_ssl_context is None:
            server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            server_ssl_context.maximum_version = PROXY_TLS_MAX_VERSION
            server_ssl_context.load_cert_chain(str(cert_path), str(key_path))
            server_ssl_context.set_alpn_protocols(['http/1.1'])
        self._server_ctx = server_ssl_context

        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: asyncio.base_events.Server | None = None
        self._started = threading.Event()
        self._error: BaseException | None = None
        self.port = listen_port

    # -- vòng đời -------------------------------------------------------

    def start(self, timeout: float = 10.0) -> None:
        """Khởi động proxy trong luồng riêng. Ném OSError nếu không bind được cổng."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._started.clear()
        self._error = None
        self._thread = threading.Thread(target=self._run, name='fleasion-proxy', daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):
            raise TimeoutError('Proxy không khởi động kịp')
        if self._error is not None:
            raise self._error  # type: ignore[misc]
        log_buffer.log('Proxy', f'Đang lắng nghe {self.listen_host}:{self.port}')

    def stop(self) -> None:
        loop, thread = self._loop, self._thread
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(loop.stop)
        if thread is not None:
            thread.join(timeout=5.0)
        self._thread = None
        self._loop = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self._error is None

    def _run(self) -> None:
        # SelectorEventLoop tránh lỗi accept WinError 10014 của Proactor trên một số máy Windows.
        loop = asyncio.SelectorEventLoop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            self._server = loop.run_until_complete(
                asyncio.start_server(
                    self._handle_client,
                    self.listen_host,
                    self.listen_port,
                    ssl=self._server_ctx,
                    backlog=128,
                )
            )
            sockets = self._server.sockets or []
            if sockets:
                self.port = sockets[0].getsockname()[1]
        except BaseException as exc:
            self._error = exc
            self._started.set()
            loop.close()
            return
        self._started.set()
        try:
            loop.run_forever()
        finally:
            try:
                self._server.close()
                loop.run_until_complete(self._server.wait_closed())
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            except Exception:
                pass
            loop.close()

    # -- upstream -------------------------------------------------------

    async def _connect_upstream(self, host: str):
        last_error: BaseException | None = None
        for attempt in range(2):
            endpoints = self._resolver.get(host)
            if attempt == 1:
                endpoints = await asyncio.get_running_loop().run_in_executor(
                    None, self._resolver.refresh, host
                )
            for ip in endpoints[:4]:
                try:
                    return await asyncio.wait_for(
                        asyncio.open_connection(
                            ip,
                            443,
                            ssl=self._upstream_ctx,
                            server_hostname=host,
                            ssl_handshake_timeout=UPSTREAM_CONNECT_TIMEOUT,
                        ),
                        timeout=UPSTREAM_CONNECT_TIMEOUT + 2,
                    )
                except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
                    last_error = exc
        raise ConnectionError(f'Không kết nối được tới {host}: {last_error or "không có IP"}')

    async def _fetch(
        self, host: str, method: str, target: str, headers: Headers, body: bytes
    ) -> tuple[str, Headers, bytes]:
        reader, writer = await self._connector(host)
        try:
            out = _without(headers, _HOP_BY_HOP)
            if body or method in ('POST', 'PUT', 'PATCH'):
                out.append(('Content-Length', str(len(body))))
            out.append(('Connection', 'close'))
            head = f'{method} {target} HTTP/1.1\r\n' + ''.join(f'{k}: {v}\r\n' for k, v in out) + '\r\n'
            writer.write(head.encode('latin-1') + body)
            await writer.drain()

            while True:
                response_head = await asyncio.wait_for(read_head(reader), UPSTREAM_IO_TIMEOUT)
                if response_head is None:
                    raise ConnectionError('Upstream đóng kết nối mà không phản hồi')
                status_line, resp_headers = response_head
                status = int(status_line.split()[1])
                if 100 <= status < 200 and status != 101:
                    continue  # bỏ qua 100 Continue / 103 Early Hints
                break

            if method == 'HEAD' or status in _NO_BODY_STATUSES or 100 <= status < 200:
                resp_body = b''
            else:
                resp_body = await asyncio.wait_for(
                    read_body(reader, resp_headers, until_eof=True), UPSTREAM_IO_TIMEOUT
                )
            return status_line, resp_headers, resp_body
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _get_dictionary(self, sha256: str) -> bytes | None:
        """Tải (và nhớ) từ điển nén dùng chung của Roblox, có kiểm tra SHA-256."""
        cached = self._dictionary_cache.get(sha256)
        if cached is not None:
            return cached
        try:
            status_line, headers, body = await self._fetch(
                DICTIONARY_HOST,
                'GET',
                f'/v2/compression-dictionaries/{sha256}',
                [
                    ('Host', DICTIONARY_HOST),
                    ('Accept', 'application/octet-stream'),
                    ('Accept-Encoding', 'identity'),
                    ('User-Agent', 'Fleasion/1.0'),
                ],
                b'',
            )
        except (OSError, ConnectionError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError) as exc:
            log_buffer.log('FastFlags', f'Không tải được từ điển nén của Roblox: {exc}')
            return None
        if not 200 <= int(status_line.split()[1]) < 300:
            log_buffer.log('FastFlags', f'Từ điển nén của Roblox trả về {status_line}')
            return None
        dictionary = decompress_body(body, header_get(headers, 'content-encoding'))
        if dictionary is None or not dictionary_matches(dictionary, sha256):
            log_buffer.log('FastFlags', 'Từ điển nén của Roblox không khớp SHA-256; giữ nguyên phản hồi')
            return None
        self._dictionary_cache[sha256] = dictionary
        return dictionary

    # -- sửa response ---------------------------------------------------

    async def _modify(
        self, path: str, headers: Headers, body: bytes
    ) -> tuple[Headers, bytes] | None:
        """Ghép FastFlag vào response; None nếu không sửa được (giữ nguyên bản gốc)."""
        encoding = header_get(headers, 'content-encoding').strip().lower()
        stripped = _without(headers, _STALE_AFTER_MODIFY | {'content-length'})

        if encoding == 'dcz':
            sha256 = dcz_dictionary_sha256(path)
            dictionary = await self._get_dictionary(sha256) if sha256 else None
            plain = decompress_dcz(body, dictionary) if dictionary is not None else None
            if dictionary is None or plain is None:
                log_buffer.log('FastFlags', 'Không giải nén được ClientSettings dạng dcz; giữ nguyên phản hồi')
                return None
            modified = self.modifier.modify_response(path, plain)
            if modified == plain:
                return None
            recompressed = compress_dcz(modified, dictionary)
            if recompressed is None:
                log_buffer.log('FastFlags', 'Không nén lại được ClientSettings dạng dcz; giữ nguyên phản hồi')
                return None
            return [*stripped, ('Content-Encoding', 'dcz')], recompressed

        plain = decompress_body(body, encoding)
        if plain is None:
            log_buffer.log('FastFlags', f'Không giải nén được ClientSettings ({encoding}); giữ nguyên phản hồi')
            return None
        modified = self.modifier.modify_response(path, plain)
        if modified == plain:
            return None
        return stripped, modified

    # -- xử lý kết nối client -------------------------------------------

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                try:
                    head = await asyncio.wait_for(read_head(reader), CLIENT_IDLE_TIMEOUT)
                except (asyncio.TimeoutError, ConnectionError, ValueError, OSError):
                    break
                if head is None:
                    break
                request_line, headers = head
                parts = request_line.split()
                if len(parts) != 3:
                    writer.write(simple_response(400, 'Bad Request', 'Bad request'))
                    break
                method, target, version = parts[0].upper(), parts[1], parts[2].upper()
                host = header_get(headers, 'host').split(':', 1)[0].strip().lower()
                if host not in self.hosts:
                    writer.write(simple_response(421, 'Misdirected Request', 'Host không được proxy này xử lý'))
                    break
                try:
                    body = await read_body(reader, headers)
                except (asyncio.IncompleteReadError, ValueError, ConnectionError):
                    break
                keep_alive = version == 'HTTP/1.1' and 'close' not in header_get(headers, 'connection').lower()

                try:
                    status_line, resp_headers, resp_body = await self._forward(method, target, host, headers, body)
                except Exception as exc:
                    log_buffer.log('Proxy', f'Lỗi chuyển tiếp {host}{target[:80]}: {exc}')
                    writer.write(simple_response(502, 'Bad Gateway', 'Không kết nối được tới Roblox'))
                    break

                writer.write(
                    build_response(
                        status_line, resp_headers, resp_body, keep_alive=keep_alive, head_request=method == 'HEAD'
                    )
                )
                await writer.drain()
                if not keep_alive:
                    break
        except (ConnectionError, asyncio.CancelledError, ssl.SSLError, OSError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _forward(
        self, method: str, target: str, host: str, headers: Headers, body: bytes
    ) -> tuple[str, Headers, bytes]:
        path = target
        applies = method == 'GET' and self.modifier.is_enabled() and self.modifier.handles_path(path)
        upstream_headers = headers
        if applies and self.modifier.requires_fresh_response():
            # Roblox thường nhận 304 cho request mỗi giây; cần một phản hồi 200 để nhận flag mới.
            upstream_headers = _without(headers, {'if-none-match', 'if-modified-since'})
            log_buffer.log('FastFlags', 'Yêu cầu một phản hồi ClientSettings mới để áp dụng FastFlag')

        status_line, resp_headers, resp_body = await self._fetch(host, method, target, upstream_headers, body)
        if applies and 200 <= int(status_line.split()[1]) < 300 and resp_body:
            result = await self._modify(path, resp_headers, resp_body)
            if result is None:
                self.modifier.prepare_for_player_launch()  # lần sau thử lại
            else:
                resp_headers, resp_body = result
        return status_line, resp_headers, resp_body
