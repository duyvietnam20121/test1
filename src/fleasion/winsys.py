"""Tích hợp Windows: quyền admin, file hosts, cài CA, tìm thư mục Roblox.

Module import được trên hệ điều hành khác để chạy test; các hàm đặc thù Windows
chỉ hoạt động khi ``sys.platform == 'win32'``.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time
import warnings
from collections.abc import Iterable
from pathlib import Path

from .log import log_buffer
from .paths import HOSTS_FILE, LOCAL_APPDATA, ROBLOX_PLAYER_EXE

IS_WINDOWS = sys.platform == 'win32'
HOSTS_MARKER = '# Fleasion proxy entry'
CREATE_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
CERTUTIL_EXE = str(Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'certutil.exe')
CA_COMMON_NAME = 'Fleasion Proxy CA'
CA_ORGANIZATION = 'Fleasion'

_PEM_BLOCK_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.DOTALL)
_HOSTS_WRITE_RETRIES = 5
_HOSTS_WRITE_DELAY = 0.2
# cacert.pem hợp lệ của Roblox có hàng chục CA gốc; file quá nhỏ nghĩa là đã hỏng.
_CACERT_MIN_CERTS = 2


# ---------------------------------------------------------------------------
# Quyền admin
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


def relaunch_as_admin(extra_args: Iterable[str] = ()) -> bool:
    """Mở lại ứng dụng với quyền admin (UAC). Trả về True nếu đã gửi yêu cầu."""
    if not IS_WINDOWS:
        return False
    args = list(sys.argv[1:]) + [a for a in extra_args if a not in sys.argv[1:]]
    if getattr(sys, 'frozen', False):
        executable, params = sys.executable, subprocess.list2cmdline(args)
    else:
        executable = sys.executable
        params = subprocess.list2cmdline(['-m', 'fleasion', *args])
    try:
        result = ctypes.windll.shell32.ShellExecuteW(  # type: ignore[attr-defined]
            None, 'runas', executable, params, None, 1
        )
    except Exception as exc:
        log_buffer.log('Admin', f'Không thể yêu cầu quyền admin: {exc}')
        return False
    return int(result) > 32


# ---------------------------------------------------------------------------
# File hosts
# ---------------------------------------------------------------------------

_DEFAULT_HOSTS = (
    '# Copyright (c) 1993-2009 Microsoft Corp.\n'
    '#\n'
    '# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\n'
    '#\n'
    '# localhost name resolution is handled within DNS itself.\n'
    '#\t127.0.0.1       localhost\n'
    '#\t::1             localhost\n'
)


def _read_hosts(path: Path) -> str:
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except FileNotFoundError:
        return _DEFAULT_HOSTS


def _write_hosts(path: Path, content: str) -> None:
    """Ghi hosts; thử ghi trực tiếp rồi đến ghi tạm + đổi tên (vượt khóa của phần mềm bảo mật)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        mode = path.stat().st_mode
        if not mode & stat.S_IWRITE:
            try:
                path.chmod(mode | stat.S_IWRITE)
            except OSError as exc:
                log_buffer.log('Hosts', f'Không bỏ được thuộc tính chỉ-đọc của hosts: {exc}')

    last_exc: OSError | None = None
    for attempt in range(_HOSTS_WRITE_RETRIES):
        try:
            path.write_text(content, encoding='utf-8')
            return
        except PermissionError as exc:
            last_exc = exc
            if attempt < _HOSTS_WRITE_RETRIES - 1:
                time.sleep(_HOSTS_WRITE_DELAY)

    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.fleasion_hosts_')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
        os.replace(temporary, path)
        log_buffer.log('Hosts', 'Đã ghi hosts bằng cách đổi tên file (vượt khóa phần mềm bảo mật)')
    except OSError as exc:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise PermissionError(
            'Không ghi được file hosts. Nếu có phần mềm bảo mật (Webroot, Kaspersky...), '
            f'hãy tắt tính năng bảo vệ file hosts. Lỗi ghi trực tiếp: {last_exc}; lỗi đổi tên: {exc}'
        ) from exc


def _is_our_hosts_line(line: str) -> bool:
    return HOSTS_MARKER in line


def _flush_dns() -> None:
    if not IS_WINDOWS:
        return
    try:
        subprocess.run(
            ['ipconfig', '/flushdns'],
            capture_output=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        pass


def hosts_conflicts(hosts: Iterable[str], path: Path | None = None) -> list[str]:
    """Các dòng hosts KHÔNG phải của Fleasion nhưng trỏ tên miền cần chặn đi nơi khác."""
    wanted = {h.lower() for h in hosts}
    conflicts: list[str] = []
    for raw in _read_hosts(path or HOSTS_FILE).splitlines():
        if _is_our_hosts_line(raw):
            continue
        line = raw.split('#', 1)[0].split()
        if len(line) >= 2 and line[0] not in ('127.0.0.1', '::1') and wanted & {n.lower() for n in line[1:]}:
            conflicts.append(raw.strip())
    return conflicts


def has_stale_hosts_entries(path: Path | None = None) -> bool:
    return any(_is_our_hosts_line(l) for l in _read_hosts(path or HOSTS_FILE).splitlines())


def add_hosts_entries(hosts: Iterable[str], path: Path | None = None) -> None:
    """Trỏ các tên miền về 127.0.0.1 (thay thế mọi dòng cũ do Fleasion thêm)."""
    path = path or HOSTS_FILE
    kept = [l for l in _read_hosts(path).splitlines() if not _is_our_hosts_line(l)]
    entries = [f'127.0.0.1 {host} {HOSTS_MARKER}' for host in sorted(set(hosts))]
    _write_hosts(path, '\n'.join([*kept, *entries]).rstrip('\n') + '\n')
    _flush_dns()
    for host in sorted(set(hosts)):
        log_buffer.log('Hosts', f'Đã chuyển hướng {host} -> 127.0.0.1')


def remove_hosts_entries(path: Path | None = None) -> bool:
    """Xóa mọi dòng do Fleasion thêm. Trả về True nếu hosts đã sạch."""
    path = path or HOSTS_FILE
    try:
        existing = _read_hosts(path)
        lines = existing.splitlines()
        kept = [l for l in lines if not _is_our_hosts_line(l)]
        if len(kept) == len(lines):
            return True
        _write_hosts(path, '\n'.join(kept).rstrip('\n') + '\n')
    except OSError as exc:
        log_buffer.log('Hosts', f'Không dọn được file hosts: {exc}')
        return False
    _flush_dns()
    log_buffer.log('Hosts', 'Đã khôi phục file hosts')
    return True


# ---------------------------------------------------------------------------
# Chứng chỉ
# ---------------------------------------------------------------------------


def _normalize_newlines(text: str) -> str:
    return text.replace('\r\n', '\n').replace('\r', '\n')


def _normalize_pem_block(pem_block: str) -> str:
    return f'{_normalize_newlines(pem_block).strip()}\n'


def ca_thumbprint_sha1(ca_pem: str) -> str:
    body = ''.join(l.strip() for l in ca_pem.splitlines() if l and not l.startswith('-----'))
    return hashlib.sha1(base64.b64decode(body)).hexdigest().upper()


def _is_fleasion_ca_block(pem_block: str) -> bool:
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            cert = x509.load_pem_x509_certificate(pem_block.encode('utf-8'))
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        return (
            cert.subject == cert.issuer
            and bool(cn and cn[0].value == CA_COMMON_NAME)
            and bool(org and org[0].value == CA_ORGANIZATION)
        )
    except Exception:
        return False


def _strip_fleasion_cas(bundle: str, current_pem: str) -> tuple[str, int, int]:
    """Bỏ mọi CA Fleasion khỏi bundle; trả (văn bản đã làm sạch, số CA Fleasion, số CA hiện tại)."""
    text = _normalize_newlines(bundle)
    current = _normalize_pem_block(current_pem)
    parts: list[str] = []
    last_end = fleasion = current_count = 0
    for match in _PEM_BLOCK_RE.finditer(text):
        parts.append(text[last_end : match.start()])
        block = match.group(0)
        if _is_fleasion_ca_block(block):
            fleasion += 1
            current_count += _normalize_pem_block(block) == current
        else:
            parts.append(block)
        last_end = match.end()
    parts.append(text[last_end:])
    return ''.join(parts), fleasion, current_count


def _certutil(*args: str, timeout: int = 20) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            [CERTUTIL_EXE, *args],
            capture_output=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception as exc:
        log_buffer.log('Certificate', f'certutil lỗi: {exc}')
        return None


def _root_store_fleasion_thumbprints() -> list[str]:
    result = _certutil('-store', 'Root')
    if result is None or result.returncode != 0:
        return []
    entries: list[tuple[str, str]] = []
    current_hash: str | None = None
    current_text: list[str] = []
    for line in (result.stdout or b'').decode('utf-8', errors='replace').splitlines():
        stripped = line.strip()
        if stripped.lower().startswith('cert hash(sha1):'):
            if current_hash is not None:
                entries.append((current_hash, '\n'.join(current_text)))
            current_hash = stripped.split(':', 1)[1].strip().replace(' ', '').upper()
            current_text = [stripped]
        elif current_hash is not None:
            current_text.append(stripped)
    if current_hash is not None:
        entries.append((current_hash, '\n'.join(current_text)))
    return [h for h, text in entries if h and CA_COMMON_NAME.lower() in text.lower()]


def install_ca_into_windows_root(ca_cert_path: Path, ca_pem: str) -> bool:
    """Tin cậy CA trong kho Root của Windows (cần cho bootstrapper/WinHTTP). Cần quyền admin."""
    thumbprint = ca_thumbprint_sha1(ca_pem)
    stale = [t for t in _root_store_fleasion_thumbprints() if t != thumbprint]
    for old in stale:
        _certutil('-delstore', 'Root', old)

    check = _certutil('-store', 'Root', thumbprint, timeout=10)
    if check is not None and check.returncode == 0:
        text = ((check.stdout or b'') + (check.stderr or b'')).decode('utf-8', errors='replace')
        if thumbprint.lower() in text.replace(' ', '').lower():
            log_buffer.log('Certificate', 'CA đã được tin cậy trong kho Root của Windows')
            return True

    result = _certutil('-addstore', '-f', 'Root', str(ca_cert_path))
    if result is not None and result.returncode == 0:
        log_buffer.log('Certificate', 'Đã cài CA vào kho Root của Windows')
        return True
    err = ((result.stderr or result.stdout or b'').decode('utf-8', errors='replace').strip()
           if result is not None else 'không chạy được certutil')
    log_buffer.log('Certificate', f'Không cài được CA vào kho Root: {err}')
    return False


def remove_ca_from_windows_root() -> int:
    """Gỡ mọi CA Fleasion khỏi kho Root; trả về số mục đã xóa."""
    removed = 0
    for thumbprint in _root_store_fleasion_thumbprints():
        result = _certutil('-delstore', 'Root', thumbprint)
        removed += bool(result is not None and result.returncode == 0)
    return removed


# ---------------------------------------------------------------------------
# Thư mục Roblox
# ---------------------------------------------------------------------------


def _has_player_exe(path: Path) -> bool:
    return os.path.isfile(os.path.join(path, ROBLOX_PLAYER_EXE))


def _scan_for_player(root: Path, max_depth: int) -> list[Path]:
    """Các thư mục (tối đa max_depth tầng dưới root) có RobloxPlayerBeta.exe."""
    results: list[Path] = []
    if not root.is_dir():
        return results
    if _has_player_exe(root):
        results.append(root)

    def recurse(path: Path, depth: int) -> None:
        try:
            for entry in os.scandir(path):
                if not entry.is_dir():
                    continue
                entry_path = Path(entry.path)
                if _has_player_exe(entry_path):
                    results.append(entry_path)
                if depth < max_depth:
                    recurse(entry_path, depth + 1)
        except OSError:
            pass

    recurse(root, 1)
    return results


def _extract_exe_from_command(command: str) -> Path | None:
    command = (command or '').strip()
    if not command:
        return None
    try:
        parts = shlex.split(command, posix=False)
    except ValueError:
        parts = command.split()
    if not parts:
        return None
    return Path(parts[0].strip('"'))


def find_roblox_dirs(*, quick: bool = False, known: Iterable[Path] = ()) -> list[Path]:
    """Tìm thư mục phiên bản Roblox Player (nơi có ``ssl/cacert.pem``).

    ``quick=True`` bỏ qua việc duyệt registry, chỉ quét lại các thư mục gốc quen thuộc
    để bắt phiên bản mới do Roblox/bootstrapper vừa tải về.
    """
    found: list[Path] = []
    seen: set[str] = set()

    def add(path: Path) -> None:
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            found.append(path)

    for path in known:
        if _has_player_exe(path):
            add(path)
        for sibling in _scan_for_player(path.parent, 1):
            add(sibling)

    for root, depth in (
        (LOCAL_APPDATA / 'Roblox' / 'Versions', 1),
        (Path(os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)')) / 'Roblox' / 'Versions', 2),
        (Path(r'C:\XboxGames\Roblox'), 2),
    ):
        for path in _scan_for_player(root, depth):
            add(path)

    if not IS_WINDOWS:
        return found

    import winreg

    try:  # Trình xử lý roblox-player:// đang dùng.
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, r'SOFTWARE\Classes\roblox-player\shell\open\command'
        ) as key:
            command, kind = winreg.QueryValueEx(key, '')
            exe = _extract_exe_from_command(command) if kind == winreg.REG_SZ else None
            if exe is not None:
                for path in _scan_for_player(exe.parent, 2):
                    add(path)
    except OSError:
        pass

    if quick:
        return found

    def check_key(key) -> None:
        try:
            value, kind = winreg.QueryValueEx(key, 'PlayerPath')
        except OSError:
            return
        value = str(value or '').replace('\x00', '').strip()
        if kind != winreg.REG_SZ or not value:
            return
        path = Path(value)
        if path.name.lower() == ROBLOX_PLAYER_EXE.lower():
            path = path.parent
        if _has_player_exe(path):
            add(path)
        else:
            for sub in _scan_for_player(path, 1):
                add(sub)

    # Bootstrapper bên thứ ba (Bloxstrap, Fishstrap...) ghi PlayerPath ở HKCU\Software\<Tên>[\<Tên con>].
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software') as hkey:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(hkey, index)
                    index += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(hkey, name) as sub:
                        check_key(sub)
                        sub_index = 0
                        while True:
                            try:
                                child = winreg.EnumKey(sub, sub_index)
                                sub_index += 1
                            except OSError:
                                break
                            try:
                                with winreg.OpenKey(sub, child) as child_key:
                                    check_key(child_key)
                            except (OSError, ValueError):
                                pass
                except OSError:
                    pass
    except OSError:
        pass
    return found


def cacert_state(ca_file: Path, ca_pem: str) -> str:
    """'current' | 'missing-ca' | 'unhealthy' | 'no-file' cho một cacert.pem."""
    try:
        text = ca_file.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return 'no-file'
    blocks = _PEM_BLOCK_RE.findall(_normalize_newlines(text))
    if len(blocks) < _CACERT_MIN_CERTS:
        return 'unhealthy'
    _cleaned, fleasion, current = _strip_fleasion_cas(text, ca_pem)
    return 'current' if fleasion == 1 and current == 1 else 'missing-ca'


def patch_cacert(ca_file: Path, ca_pem: str) -> bool:
    """Đảm bảo cacert.pem có đúng một CA Fleasion hiện tại. Trả về True nếu đã sửa file."""
    existing = ca_file.read_text(encoding='utf-8', errors='replace')
    cleaned, _fleasion, _current = _strip_fleasion_cas(existing, ca_pem)
    cleaned = cleaned.rstrip('\n')
    current = _normalize_pem_block(ca_pem)
    updated = f'{cleaned}\n{current}' if cleaned else current
    if updated == _normalize_newlines(existing):
        return False

    mode = ca_file.stat().st_mode
    read_only = not mode & stat.S_IWRITE
    if read_only:
        ca_file.chmod(mode | stat.S_IWRITE)
    try:
        ca_file.write_text(updated, encoding='utf-8')
    finally:
        if read_only:
            try:
                ca_file.chmod(ca_file.stat().st_mode & ~stat.S_IWRITE)
            except OSError:
                pass
    return True


def install_ca_into_roblox(ca_pem: str, dirs: Iterable[Path]) -> tuple[int, int]:
    """Vá ``ssl/cacert.pem`` của từng bản Roblox. Trả về (số bản đã vá, số bản lỗi)."""
    patched = failed = 0
    for directory in dirs:
        ca_file = directory / 'ssl' / 'cacert.pem'
        state = cacert_state(ca_file, ca_pem)
        if state == 'current':
            continue
        if state in ('no-file', 'unhealthy'):
            log_buffer.log('Certificate', f'Bỏ qua {directory.name}: cacert.pem {state}')
            failed += state == 'unhealthy'
            continue
        try:
            patch_cacert(ca_file, ca_pem)
            patched += 1
            log_buffer.log('Certificate', f'Đã cài CA vào {directory.name}')
        except (OSError, UnicodeDecodeError) as exc:
            failed += 1
            log_buffer.log('Certificate', f'Không ghi được CA vào {directory.name}: {exc}')
    return patched, failed


def remove_ca_from_roblox(dirs: Iterable[Path], ca_pem: str) -> int:
    """Gỡ CA Fleasion khỏi cacert.pem của các bản Roblox. Trả về số file đã sửa."""
    changed = 0
    for directory in dirs:
        ca_file = directory / 'ssl' / 'cacert.pem'
        try:
            text = ca_file.read_text(encoding='utf-8', errors='replace')
            cleaned, fleasion, _ = _strip_fleasion_cas(text, ca_pem)
            if not fleasion:
                continue
            ca_file.write_text(cleaned.rstrip('\n') + '\n', encoding='utf-8')
            changed += 1
        except OSError:
            continue
    return changed


# ---------------------------------------------------------------------------
# Tiến trình Roblox
# ---------------------------------------------------------------------------


def is_roblox_running() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        result = subprocess.run(
            ['tasklist', '/FI', f'IMAGENAME eq {ROBLOX_PLAYER_EXE}', '/NH'],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=CREATE_NO_WINDOW,
        )
    except Exception:
        return False
    return ROBLOX_PLAYER_EXE.lower() in (result.stdout or '').lower()
