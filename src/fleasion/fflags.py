"""FastFlags: lưu cấu hình, ghép flag vào ClientSettings, profile.

Giữ nguyên định dạng ``settings.json`` của Fleasion gốc (các khóa
``custom_fflags``, ``custom_fflags_enabled``, ``custom_fflag_disabled``).
Các khóa khác trong file được giữ nguyên khi lưu.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import threading
import zlib
from pathlib import Path
from typing import Any

from .log import log_buffer
from .paths import CONFIG_FILE, FLAG_CACHE_PATH, PROFILES_DIR

CLIENT_SETTINGS_APPLICATION_PATH = '/settings/application/'
CLIENT_SETTINGS_COMPRESSED_PATH = '/settings-compressed/application/'
BOOTSTRAPPER_CLIENT_SETTINGS_PLATFORM = 'PCClientBootstrapper'
DYNAMIC_VARIABLE_RELOAD_INTERVAL_FLAG = 'DFIntSecondsBetweenDynamicVariableReloading'
DYNAMIC_VARIABLE_RELOAD_INTERVAL_SECONDS = '1'

DCZ_DICTIONARY_PATH_RE = re.compile(r'/([0-9a-f]{64})\.dcz(?:$|[?])', re.IGNORECASE)
_MAX_DECOMPRESSED = 64 * 1024 * 1024


# ---------------------------------------------------------------------------
# Chuẩn hóa dữ liệu
# ---------------------------------------------------------------------------


def normalize_flag_value(value: Any) -> str:
    """Trả về dạng chuỗi mà Roblox dùng cho giá trị FastFlag."""
    if isinstance(value, bool):
        return 'True' if value else 'False'
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return str(value)
    raise ValueError('FastFlag values must be strings, numbers, or booleans')


def normalize_custom_fflags(value: Any) -> dict[str, str]:
    """Kiểm tra và chuẩn hóa dict FastFlag; bỏ qua mục không hợp lệ."""
    if not isinstance(value, dict):
        return {}
    normalized: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip()
        if not name:
            continue
        try:
            normalized[name] = normalize_flag_value(raw_value)
        except ValueError:
            continue
    return normalized


def _normalize_disabled(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return sorted({str(name).strip() for name in value if str(name).strip()})


# ---------------------------------------------------------------------------
# Lưu cấu hình
# ---------------------------------------------------------------------------


class Settings:
    """Đọc/ghi ``settings.json`` (an toàn đa luồng, ghi nguyên tử)."""

    def __init__(self, path: Path | None = None) -> None:
        self._path = Path(path) if path is not None else CONFIG_FILE
        self._lock = threading.RLock()
        self._raw: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        with self._lock:
            try:
                data = json.loads(self._path.read_text(encoding='utf-8'))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                data = {}
            self._raw = data if isinstance(data, dict) else {}

    def save(self) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._path.with_name(f'.{self._path.name}.{os.getpid()}.tmp')
            try:
                temporary.write_text(json.dumps(self._raw, indent=2, ensure_ascii=False), 'utf-8')
                temporary.replace(self._path)
            finally:
                temporary.unlink(missing_ok=True)

    @property
    def enabled(self) -> bool:
        with self._lock:
            return bool(self._raw.get('custom_fflags_enabled', False))

    @enabled.setter
    def enabled(self, value: bool) -> None:
        with self._lock:
            self._raw['custom_fflags_enabled'] = bool(value)

    @property
    def flags(self) -> dict[str, str]:
        with self._lock:
            return normalize_custom_fflags(self._raw.get('custom_fflags', {}))

    @flags.setter
    def flags(self, value: dict) -> None:
        with self._lock:
            self._raw['custom_fflags'] = normalize_custom_fflags(value)

    @property
    def disabled(self) -> list[str]:
        with self._lock:
            return _normalize_disabled(self._raw.get('custom_fflag_disabled', []))

    @disabled.setter
    def disabled(self, value) -> None:
        with self._lock:
            self._raw['custom_fflag_disabled'] = _normalize_disabled(list(value))

    @property
    def warning_accepted(self) -> bool:
        with self._lock:
            return bool(self._raw.get('custom_fflags_warning_accepted', False))

    @warning_accepted.setter
    def warning_accepted(self, value: bool) -> None:
        with self._lock:
            self._raw['custom_fflags_warning_accepted'] = bool(value)


# ---------------------------------------------------------------------------
# Nén / giải nén
# ---------------------------------------------------------------------------


def decompress_body(body: bytes, content_encoding: str) -> bytes | None:
    """Giải nén theo ``content-encoding``; ``None`` nếu không giải được."""
    encoding = (content_encoding or '').strip().lower()
    if not body or encoding in ('', 'identity'):
        return body
    try:
        if encoding in ('gzip', 'x-gzip'):
            return gzip.decompress(body)
        if encoding == 'deflate':
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
        if encoding == 'zstd':
            import zstandard

            return zstandard.ZstdDecompressor().decompress(body, max_output_size=_MAX_DECOMPRESSED)
        if encoding == 'br':
            import brotli  # type: ignore[import-not-found]

            return brotli.decompress(body)
    except Exception:
        return None
    return None


def dcz_dictionary_sha256(path: str) -> str | None:
    match = DCZ_DICTIONARY_PATH_RE.search(str(path or ''))
    return match.group(1).lower() if match else None


def _dcz_dict(dictionary: bytes):
    import zstandard

    return zstandard.ZstdCompressionDict(dictionary, dict_type=zstandard.DICT_TYPE_RAWCONTENT)


def decompress_dcz(body: bytes, dictionary: bytes) -> bytes | None:
    try:
        import zstandard

        return zstandard.ZstdDecompressor(dict_data=_dcz_dict(dictionary)).decompress(
            body, max_output_size=_MAX_DECOMPRESSED
        )
    except Exception:
        return None


def compress_dcz(body: bytes, dictionary: bytes) -> bytes | None:
    try:
        import zstandard

        return zstandard.ZstdCompressor(dict_data=_dcz_dict(dictionary)).compress(body)
    except Exception:
        return None


def dictionary_matches(dictionary: bytes, expected_sha256: str) -> bool:
    return hashlib.sha256(dictionary).hexdigest() == expected_sha256


# ---------------------------------------------------------------------------
# Bộ ghép flag
# ---------------------------------------------------------------------------


class FFlagModifier:
    """Ghép flag của người dùng vào phản hồi ClientSettings của Roblox."""

    def __init__(self, settings: Settings, flag_cache_path: Path | None = None) -> None:
        self.settings = settings
        self._flag_cache_path = Path(flag_cache_path) if flag_cache_path else FLAG_CACHE_PATH
        self._seeded_names: set[str] = set()
        self._last_fresh_flags: tuple[tuple[str, str], ...] | None = None
        self._lock = threading.RLock()

    # -- trạng thái -----------------------------------------------------

    def is_enabled(self) -> bool:
        return self.settings.enabled

    @staticmethod
    def handles_path(path: str) -> bool:
        """Chỉ sửa ClientSettings của Player; bootstrapper được chuyển tiếp nguyên vẹn."""
        path_only = str(path or '').split('?', 1)[0]
        is_application_settings = (
            CLIENT_SETTINGS_APPLICATION_PATH in path_only
            or CLIENT_SETTINGS_COMPRESSED_PATH in path_only
        )
        return is_application_settings and BOOTSTRAPPER_CLIENT_SETTINGS_PLATFORM not in path_only

    def runtime_flags(self) -> dict[str, str]:
        """Flag đang bật, kèm flag phụ giúp Roblox nạp lại mỗi giây (không lưu xuống đĩa)."""
        disabled = set(self.settings.disabled)
        flags = {n: v for n, v in self.settings.flags.items() if n not in disabled}
        flags[DYNAMIC_VARIABLE_RELOAD_INTERVAL_FLAG] = DYNAMIC_VARIABLE_RELOAD_INTERVAL_SECONDS
        return flags

    def requires_fresh_response(self) -> bool:
        """True đúng một lần sau mỗi thay đổi: cần trả 200 thay vì 304 để Roblox nhận flag mới."""
        with self._lock:
            active = tuple(sorted(self.runtime_flags().items()))
            if active == self._last_fresh_flags:
                return False
            self._last_fresh_flags = active
            return True

    def prepare_for_player_launch(self) -> None:
        with self._lock:
            self._last_fresh_flags = None

    # -- sửa response ---------------------------------------------------

    def modify_response(self, path: str, body: bytes) -> bytes:
        """Trả về JSON ClientSettings đã ghép flag (hoặc nguyên body nếu không áp dụng)."""
        if not self.is_enabled() or not self.handles_path(path):
            return body
        flags = self.runtime_flags()
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            log_buffer.log('FastFlags', f'Không đọc được ClientSettings: {path[:160]}')
            return body
        if not isinstance(payload, dict):
            return body
        application_settings = payload.get('applicationSettings')
        if not isinstance(application_settings, dict):
            return body
        application_settings.update(flags)
        log_buffer.log('FastFlags', f'Đã ghép {len(flags)} FastFlag vào phản hồi ClientSettings')
        return json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

    # -- flag_cache.dat -------------------------------------------------

    def prime_flag_cache(self) -> bool:
        """Ghi flag vào ``flag_cache.dat`` để các flag đọc sớm (vd. FPS) có hiệu lực ngay.

        Bố cục: 4 byte độ dài chữ ký, chữ ký, 1 byte kiểu nén, rồi JSON. Chỉ ghi khi
        file không nén (kiểu 0). Khi tắt, chỉ xóa các flag do Fleasion đã ghi trước đó.
        """
        cache_path = self._flag_cache_path
        try:
            raw = cache_path.read_bytes()
            if len(raw) < 5:
                return False
            signature_length = int.from_bytes(raw[:4], 'little')
            compression_offset = 4 + signature_length
            payload_offset = compression_offset + 1
            if payload_offset >= len(raw) or raw[compression_offset] != 0:
                return False
            payload = json.loads(raw[payload_offset:])
            application_settings = payload.get('applicationSettings')
            if not isinstance(application_settings, dict):
                return False

            flags = self.runtime_flags() if self.is_enabled() else {}
            saved_names = set(self.settings.flags)
            stale = (self._seeded_names | saved_names | {DYNAMIC_VARIABLE_RELOAD_INTERVAL_FLAG}) - set(flags)
            removed = {n for n in stale if application_settings.pop(n, None) is not None}
            application_settings.update(flags)
            updated = raw[:payload_offset] + json.dumps(
                payload, separators=(',', ':'), ensure_ascii=False
            ).encode('utf-8')
            self._seeded_names = set(flags)
            if updated == raw:
                return False
            temporary = cache_path.with_name(f'.{cache_path.name}.{os.getpid()}.tmp')
            try:
                temporary.write_bytes(updated)
                temporary.replace(cache_path)
            finally:
                temporary.unlink(missing_ok=True)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, AttributeError):
            return False

        if flags:
            log_buffer.log('FastFlags', f'Đã ghi sẵn {len(flags)} FastFlag vào flag cache của Roblox')
        elif removed:
            log_buffer.log('FastFlags', f'Đã xóa {len(removed)} FastFlag khỏi flag cache của Roblox')
        return True


# ---------------------------------------------------------------------------
# Profile
# ---------------------------------------------------------------------------


class ProfileManager:
    """Lưu các bộ FastFlag có tên dưới dạng file JSON dễ chia sẻ."""

    def __init__(self, directory: Path | None = None) -> None:
        self._directory = Path(directory) if directory is not None else PROFILES_DIR

    @staticmethod
    def _normalise_name(name: str) -> str:
        name = str(name or '').strip()
        if name.lower().endswith('.json'):
            name = name[:-5].strip()
        if not name:
            raise ValueError('Tên profile không được để trống.')
        if name in {'.', '..'} or any(c in name for c in '\\/:*?"<>|'):
            raise ValueError('Tên profile chứa ký tự không hợp lệ.')
        return name

    def _path_for(self, name: str) -> Path:
        return self._directory / f'{self._normalise_name(name)}.json'

    def list_profiles(self) -> list[str]:
        if not self._directory.exists():
            return []
        return sorted((p.stem for p in self._directory.glob('*.json') if p.is_file()), key=str.casefold)

    def save(self, name: str, flags: dict) -> str:
        path = self._path_for(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        text = json.dumps(normalize_custom_fflags(flags), indent=2, ensure_ascii=False)
        path.write_text(text + '\n', encoding='utf-8')
        return path.stem

    def load(self, name: str) -> dict[str, str]:
        path = self._path_for(name)
        try:
            payload = json.loads(path.read_text(encoding='utf-8'))
        except FileNotFoundError:
            raise ValueError('Profile không còn tồn tại.') from None
        except json.JSONDecodeError as exc:
            raise ValueError(f'Profile không phải JSON hợp lệ: {exc.msg}.') from exc
        if not isinstance(payload, dict):
            raise ValueError('JSON của profile phải là các cặp tên/giá trị FastFlag.')
        flags = normalize_custom_fflags(payload)
        if len(flags) != len(payload):
            raise ValueError('Mỗi giá trị FastFlag phải là chuỗi, số hoặc boolean.')
        return flags

    def delete(self, name: str) -> None:
        try:
            self._path_for(name).unlink()
        except FileNotFoundError:
            raise ValueError('Profile không còn tồn tại.') from None

    def rename(self, old_name: str, new_name: str) -> str:
        old_path, new_path = self._path_for(old_name), self._path_for(new_name)
        if new_path.exists() and new_path != old_path:
            raise ValueError('Đã có profile trùng tên.')
        try:
            old_path.rename(new_path)
        except FileNotFoundError:
            raise ValueError('Profile không còn tồn tại.') from None
        return new_path.stem
