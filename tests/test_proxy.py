import asyncio
import gzip
import hashlib
import json
import socket
import ssl
import threading

import pytest
import zstandard

from fleasion.certs import generate_ca, generate_multi_host_cert
from fleasion.fflags import FFlagModifier, Settings
from fleasion.proxy import (
    CLIENT_SETTINGS_HOSTS,
    ClientSettingsProxy,
    UpstreamResolver,
    dns_query_udp,
)

HOST = 'clientsettings.roblox.com'
PATH = '/v2/settings/application/PCDesktopClient'


class FakeUpstream:
    """Máy chủ HTTP giả đóng vai Roblox; ghi lại request nhận được."""

    def __init__(self):
        self.routes = {}
        self.requests = []
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(5)

    def _run(self):
        asyncio.set_event_loop(self._loop)
        self._server = self._loop.run_until_complete(asyncio.start_server(self._handle, '127.0.0.1', 0))
        self.port = self._server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    async def _handle(self, reader, writer):
        head = b''
        while not head.endswith(b'\r\n\r\n'):
            chunk = await reader.readline()
            if not chunk:
                return
            head += chunk
        lines = head.decode('latin-1').split('\r\n')
        method, target, _ = lines[0].split()
        headers = {l.split(':', 1)[0].lower(): l.split(':', 1)[1].strip() for l in lines[1:] if ':' in l}
        self.requests.append((method, target, headers))
        status, resp_headers, body, chunked = self.routes[target]
        out = f'HTTP/1.1 {status} X\r\n'
        for k, v in resp_headers.items():
            out += f'{k}: {v}\r\n'
        if chunked:
            out += 'Transfer-Encoding: chunked\r\n\r\n'
            writer.write(out.encode())
            mid = len(body) // 2
            for part in (body[:mid], body[mid:]):
                writer.write(f'{len(part):x}\r\n'.encode() + part + b'\r\n')
            writer.write(b'0\r\n\r\n')
        else:
            if status != 304:
                out += f'Content-Length: {len(body)}\r\n'
            writer.write(out.encode() + b'\r\n' + (b'' if status == 304 else body))
        await writer.drain()
        writer.close()

    def route(self, target, body=b'', status=200, headers=None, chunked=False):
        self.routes[target] = (status, headers or {}, body, chunked)

    def stop(self):
        self._loop.call_soon_threadsafe(self._loop.stop)


@pytest.fixture
def env(tmp_path):
    upstream = FakeUpstream()
    settings = Settings(tmp_path / 'settings.json')
    settings.enabled = True
    settings.flags = {'DFIntTaskSchedulerTargetFps': '999', 'FFlagFoo': True}
    modifier = FFlagModifier(settings, flag_cache_path=tmp_path / 'flag_cache.dat')

    ca_dir = tmp_path / 'ca'
    ca_cert, ca_key = generate_ca(ca_dir)
    cert, key = generate_multi_host_cert('test-leaf', CLIENT_SETTINGS_HOSTS, ca_cert, ca_key, ca_dir)

    async def connector(host):
        return await asyncio.open_connection('127.0.0.1', upstream.port)

    proxy = ClientSettingsProxy(modifier, cert, key, UpstreamResolver(), listen_port=0, connector=connector)
    proxy.start()

    client_ctx = ssl.create_default_context(cafile=str(ca_cert))

    def request(path=PATH, headers=None, host=HOST, method='GET', sock=None):
        own = sock is None
        if own:
            raw = socket.create_connection(('127.0.0.1', proxy.port), timeout=5)
            sock = client_ctx.wrap_socket(raw, server_hostname=HOST)
        extra = ''.join(f'{k}: {v}\r\n' for k, v in (headers or {}).items())
        sock.sendall(f'{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}Connection: {"close" if own else "keep-alive"}\r\n\r\n'.encode())
        data = b''
        while b'\r\n\r\n' not in data:
            data += sock.recv(65536)
        head, _, rest = data.partition(b'\r\n\r\n')
        lines = head.decode().split('\r\n')
        status = int(lines[0].split()[1])
        resp_headers = {l.split(':', 1)[0].lower(): l.split(':', 1)[1].strip() for l in lines[1:]}
        length = int(resp_headers.get('content-length', 0)) if status not in (204, 304) else 0
        while len(rest) < length:
            rest += sock.recv(65536)
        if own:
            sock.close()
        return status, resp_headers, rest

    yield upstream, settings, modifier, request, client_ctx, proxy
    proxy.stop()
    upstream.stop()


BASE = {'applicationSettings': {'FFlagExisting': 'True'}}


def test_identity_response_gets_flags(env):
    upstream, *_, request, _ctx, _proxy = env
    upstream.route(PATH, json.dumps(BASE).encode(), headers={'Content-Type': 'application/json', 'ETag': 'abc'})
    status, headers, body = request()
    flags = json.loads(body)['applicationSettings']
    assert status == 200
    assert flags['DFIntTaskSchedulerTargetFps'] == '999'
    assert flags['FFlagFoo'] == 'True'
    assert flags['FFlagExisting'] == 'True'
    assert flags['DFIntSecondsBetweenDynamicVariableReloading'] == '1'
    assert int(headers['content-length']) == len(body)
    assert 'etag' not in headers


def test_disabled_is_passthrough(env):
    upstream, settings, _m, request, *_ = env
    settings.enabled = False
    original = json.dumps(BASE).encode()
    upstream.route(PATH, original)
    status, _h, body = request()
    assert status == 200 and body == original


def test_gzip_response_is_decoded_and_modified(env):
    upstream, *_, request, _c, _p = env
    upstream.route(PATH, gzip.compress(json.dumps(BASE).encode()), headers={'Content-Encoding': 'gzip'})
    status, headers, body = request(headers={'Accept-Encoding': 'gzip'})
    assert 'content-encoding' not in headers
    assert json.loads(body)['applicationSettings']['FFlagFoo'] == 'True'


def test_chunked_upstream(env):
    upstream, *_, request, _c, _p = env
    upstream.route(PATH, json.dumps(BASE).encode(), chunked=True)
    status, _h, body = request()
    assert json.loads(body)['applicationSettings']['FFlagFoo'] == 'True'


def test_dcz_roundtrip(env):
    upstream, *_, request, _c, _p = env
    dictionary = bytes(range(256)) * 200
    sha = hashlib.sha256(dictionary).hexdigest()
    zdict = zstandard.ZstdCompressionDict(dictionary, dict_type=zstandard.DICT_TYPE_RAWCONTENT)
    compressed = zstandard.ZstdCompressor(dict_data=zdict).compress(json.dumps(BASE).encode())
    path = f'/v2/settings-compressed/application/PCDesktopClient/{sha}.dcz'
    upstream.route(path, compressed, headers={'Content-Encoding': 'dcz'})
    upstream.route(f'/v2/compression-dictionaries/{sha}', dictionary)
    status, headers, body = request(path=path, headers={'Accept-Encoding': 'dcz'})
    assert headers['content-encoding'] == 'dcz'
    plain = zstandard.ZstdDecompressor(dict_data=zdict).decompress(body)
    assert json.loads(plain)['applicationSettings']['FFlagFoo'] == 'True'


def test_dcz_bad_dictionary_keeps_original(env):
    upstream, *_, request, _c, _p = env
    sha = 'a' * 64
    path = f'/v2/settings-compressed/application/PCDesktopClient/{sha}.dcz'
    upstream.route(path, b'not-really-compressed', headers={'Content-Encoding': 'dcz'})
    upstream.route(f'/v2/compression-dictionaries/{sha}', b'wrong dictionary')
    status, headers, body = request(path=path)
    assert status == 200 and body == b'not-really-compressed' and headers['content-encoding'] == 'dcz'


def test_fresh_response_once_then_conditional_kept(env):
    upstream, *_, request, _c, _p = env
    upstream.route(PATH, json.dumps(BASE).encode())
    request(headers={'If-None-Match': 'v1'})
    first = upstream.requests[-1][2]
    assert 'if-none-match' not in first
    upstream.route(PATH, b'', status=304)
    status, _h, body = request(headers={'If-None-Match': 'v1'})
    assert status == 304 and body == b''
    assert upstream.requests[-1][2]['if-none-match'] == 'v1'


def test_flag_change_triggers_fresh_response_again(env):
    upstream, settings, _m, request, *_ = env
    upstream.route(PATH, json.dumps(BASE).encode())
    request(headers={'If-None-Match': 'v1'})
    settings.flags = {'FFlagNew': 'True'}
    request(headers={'If-None-Match': 'v1'})
    assert 'if-none-match' not in upstream.requests[-1][2]


def test_bootstrapper_not_modified(env):
    upstream, *_, request, _c, _p = env
    path = '/v2/settings/application/PCClientBootstrapper'
    original = json.dumps(BASE).encode()
    upstream.route(path, original)
    status, _h, body = request(path=path)
    assert body == original


def test_keep_alive_two_requests(env):
    upstream, *_, request, ctx, proxy = env
    upstream.route(PATH, json.dumps(BASE).encode())
    raw = socket.create_connection(('127.0.0.1', proxy.port), timeout=5)
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    for _ in range(2):
        status, _h, body = request(sock=sock)
        assert status == 200 and b'FFlagFoo' in body
    sock.close()


def test_unknown_host_rejected(env):
    *_, request, _c, _p = env
    status, _h, _b = request(host='example.com')
    assert status == 421


def test_upstream_failure_gives_502(env):
    upstream, *_, request, _c, proxy = env

    async def broken(host):
        raise ConnectionError('boom')

    proxy._connector = broken
    status, _h, _b = request()
    assert status == 502


def test_dns_query_parser():
    import struct

    original_sendto = socket.socket.sendto
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]

    def serve():
        data, addr = sock.recvfrom(512)
        question = data[12:]
        answer = b'\xc0\x0c' + struct.pack('>HHIH', 1, 1, 60, 4) + bytes([203, 0, 113, 7])
        reply = data[:2] + struct.pack('>HHHHH', 0x8180, 1, 1, 0, 0) + question + answer
        original_sendto(sock, reply, addr)  # dùng bản gốc, không phải bản đã mock

    threading.Thread(target=serve, daemon=True).start()

    def patched(self, packet, address):
        return original_sendto(self, packet, ('127.0.0.1', port))

    socket.socket.sendto = patched
    try:
        assert dns_query_udp(HOST, '9.9.9.9', timeout=2) == ['203.0.113.7']
    finally:
        socket.socket.sendto = original_sendto
        sock.close()
