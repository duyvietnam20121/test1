"""Điều phối vòng đời: chứng chỉ, hosts, proxy và theo dõi Roblox."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import winsys
from .certs import generate_ca, generate_multi_host_cert, get_ca_pem
from .fflags import FFlagModifier, Settings
from .log import log_buffer
from .paths import PROXY_CA_DIR
from .proxy import CLIENT_SETTINGS_HOSTS, ClientSettingsProxy, UpstreamResolver

LEAF_CERT_NAME = 'fleasion-clientsettings'
WATCH_INTERVAL_SECONDS = 3.0


class ServiceError(RuntimeError):
    """Lỗi khởi động có mã để GUI hiển thị thông báo phù hợp."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass
class ServiceStatus:
    running: bool = False
    hosts_redirected: bool = False
    root_ca_trusted: bool = False
    roblox_installs: int = 0
    roblox_patched: int = 0
    roblox_running: bool = False
    last_error: str = ''
    conflicts: list[str] = field(default_factory=list)


class FleasionService:
    """Khởi động/dừng toàn bộ phần chặn ClientSettings."""

    def __init__(
        self,
        settings: Settings,
        *,
        ca_dir: Path | None = None,
        listen_port: int = 443,
    ) -> None:
        self.settings = settings
        self.modifier = FFlagModifier(settings)
        self.status = ServiceStatus()
        self._ca_dir = Path(ca_dir) if ca_dir else PROXY_CA_DIR
        self._listen_port = listen_port
        self._proxy: ClientSettingsProxy | None = None
        self._ca_pem = ''
        self._roblox_dirs: list[Path] = []
        self._stop_event = threading.Event()
        self._watcher: threading.Thread | None = None
        self._lock = threading.RLock()

    # -- vòng đời -------------------------------------------------------

    def start(self) -> None:
        """Thiết lập mọi thứ. Ném ``ServiceError`` nếu không thể (đã tự dọn trước khi ném)."""
        with self._lock:
            if self.status.running:
                return
            if not winsys.is_admin():
                raise ServiceError('admin_required', 'Cần chạy với quyền Administrator để sửa file hosts và cài chứng chỉ.')

            try:
                ca_cert, ca_key = generate_ca(self._ca_dir)
                cert_path, key_path = generate_multi_host_cert(
                    LEAF_CERT_NAME, CLIENT_SETTINGS_HOSTS, ca_cert, ca_key, self._ca_dir
                )
                self._ca_pem = get_ca_pem(ca_cert)
            except Exception as exc:
                raise ServiceError('cert_failed', f'Không tạo được chứng chỉ: {exc}') from exc

            # 1) Dọn hosts cũ (sau sự cố) rồi mới phân giải IP thật, nếu không sẽ nhận 127.0.0.1.
            if winsys.has_stale_hosts_entries():
                log_buffer.log('Hosts', 'Phát hiện mục hosts cũ của Fleasion, đang dọn')
                winsys.remove_hosts_entries()
            self.status.conflicts = winsys.hosts_conflicts(CLIENT_SETTINGS_HOSTS)
            for line in self.status.conflicts:
                log_buffer.log('Hosts', f'Cảnh báo: dòng hosts khác trỏ tên miền Roblox: {line}')

            resolver = UpstreamResolver()
            resolver.prime(CLIENT_SETTINGS_HOSTS)
            if not any(resolver.get(host) for host in CLIENT_SETTINGS_HOSTS):
                raise ServiceError('dns_failed', 'Không tìm được IP thật của máy chủ ClientSettings. Kiểm tra mạng/VPN.')

            # 2) Chứng chỉ phải được tin cậy trước khi Roblox bị chuyển hướng tới proxy.
            self.status.root_ca_trusted = winsys.install_ca_into_windows_root(ca_cert, self._ca_pem)
            self._refresh_roblox_dirs(full=True)

            # 3) Bật proxy rồi mới trỏ hosts, tránh lúc hosts đã đổi mà chưa có ai lắng nghe.
            proxy = ClientSettingsProxy(self.modifier, cert_path, key_path, resolver, listen_port=self._listen_port)
            try:
                proxy.start()
            except OSError as exc:
                raise ServiceError(
                    'bind_failed',
                    f'Không mở được cổng {self._listen_port} (đang bị chương trình khác dùng?): {exc}',
                ) from exc
            self._proxy = proxy

            try:
                winsys.add_hosts_entries(CLIENT_SETTINGS_HOSTS)
            except OSError as exc:
                proxy.stop()
                self._proxy = None
                raise ServiceError('hosts_failed', str(exc)) from exc
            self.status.hosts_redirected = True
            self.status.running = True
            self.status.last_error = ''

            self.modifier.prepare_for_player_launch()
            self._prime_if_idle()
            self._stop_event.clear()
            self._watcher = threading.Thread(target=self._watch, name='fleasion-watch', daemon=True)
            self._watcher.start()
            log_buffer.log('Service', 'Fleasion đã sẵn sàng')

    def stop(self) -> None:
        """Dừng proxy và trả hosts về như cũ. An toàn khi gọi nhiều lần."""
        with self._lock:
            self._stop_event.set()
            watcher, self._watcher = self._watcher, None
            if watcher is not None and watcher is not threading.current_thread():
                watcher.join(timeout=5.0)
            winsys.remove_hosts_entries()
            if self._proxy is not None:
                self._proxy.stop()
                self._proxy = None
            self.status.running = False
            self.status.hosts_redirected = False
            log_buffer.log('Service', 'Fleasion đã dừng')

    def cleanup_everything(self) -> None:
        """Gỡ hoàn toàn: hosts, CA trong kho Root và trong cacert.pem của Roblox."""
        winsys.remove_hosts_entries()
        pem = self._ca_pem
        if not pem:
            ca_file = self._ca_dir / 'ca.crt'
            pem = ca_file.read_text(encoding='utf-8') if ca_file.exists() else ''
        removed_root = winsys.remove_ca_from_windows_root()
        removed_roblox = winsys.remove_ca_from_roblox(winsys.find_roblox_dirs(), pem) if pem else 0
        log_buffer.log('Service', f'Đã gỡ CA: {removed_root} ở kho Root, {removed_roblox} ở Roblox')

    # -- áp dụng thay đổi -------------------------------------------------

    def apply_settings(self) -> None:
        """Gọi sau khi người dùng đổi FastFlag: ghi sẵn cache nếu Roblox đang đóng."""
        self._prime_if_idle()

    def _prime_if_idle(self) -> None:
        if not winsys.is_roblox_running():
            self.modifier.prime_flag_cache()

    # -- Roblox ---------------------------------------------------------

    def _refresh_roblox_dirs(self, *, full: bool) -> None:
        dirs = winsys.find_roblox_dirs(quick=not full, known=self._roblox_dirs)
        if full and not dirs:
            log_buffer.log('Certificate', 'Chưa tìm thấy bản cài Roblox nào để vá chứng chỉ')
        self._roblox_dirs = dirs
        patched, failed = winsys.install_ca_into_roblox(self._ca_pem, dirs)
        self.status.roblox_installs = len(dirs)
        ok = sum(
            winsys.cacert_state(d / 'ssl' / 'cacert.pem', self._ca_pem) == 'current' for d in dirs
        )
        self.status.roblox_patched = ok
        if failed:
            self.status.last_error = f'{failed} bản Roblox có cacert.pem không hợp lệ'

    def _watch(self) -> None:
        """Vá CA cho phiên bản Roblox mới và ghi lại flag cache khi Roblox thoát."""
        was_running = winsys.is_roblox_running()
        while not self._stop_event.wait(WATCH_INTERVAL_SECONDS):
            try:
                self._refresh_roblox_dirs(full=False)
                running = winsys.is_roblox_running()
                self.status.roblox_running = running
                if was_running and not running:
                    self.modifier.prepare_for_player_launch()
                    self.modifier.prime_flag_cache()
                was_running = running
            except Exception as exc:  # luồng nền không được chết vì lỗi lặt vặt
                log_buffer.log('Service', f'Lỗi theo dõi Roblox: {exc}')
