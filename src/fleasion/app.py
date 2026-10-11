"""Điểm vào: kiểm tra quyền admin, khởi động dịch vụ proxy và giao diện."""

from __future__ import annotations

import argparse
import atexit
import sys
import threading

from . import winsys
from .fflags import Settings
from .log import log_buffer
from .paths import CONFIG_DIR
from .service import FleasionService, ServiceError


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog='fleasion', description='Chỉnh FastFlag Roblox qua proxy ClientSettings.')
    parser.add_argument('--cleanup', action='store_true', help='Dọn mục hosts do Fleasion để lại rồi thoát.')
    parser.add_argument(
        '--uninstall',
        action='store_true',
        help='Như --cleanup, đồng thời gỡ CA khỏi kho Root Windows và cacert.pem của Roblox.',
    )
    parser.add_argument('--no-proxy', action='store_true', help='Chỉ mở giao diện chỉnh sửa, không chạy proxy.')
    return parser.parse_args(argv)


def _run_cleanup(uninstall: bool) -> int:
    if not winsys.is_admin():
        if winsys.relaunch_as_admin():
            return 0
        print('Cần quyền Administrator để dọn file hosts.', file=sys.stderr)
        return 1
    service = FleasionService(Settings())
    if uninstall:
        service.cleanup_everything()
    elif not winsys.remove_hosts_entries():
        return 1
    print('Đã dọn xong.')
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if sys.platform != 'win32':
        print('Fleasion (bản FastFlags) chỉ hỗ trợ Windows.', file=sys.stderr)
        return 1
    if args.cleanup or args.uninstall:
        return _run_cleanup(args.uninstall)

    from PyQt6.QtCore import QLockFile, QObject, pyqtSignal
    from PyQt6.QtWidgets import QApplication, QMessageBox

    from .gui import MainWindow

    app = QApplication(sys.argv[:1])
    app.setApplicationName('Fleasion')
    app.setQuitOnLastWindowClosed(False)

    run_proxy = not args.no_proxy
    if run_proxy and not winsys.is_admin():
        answer = QMessageBox.question(
            None,
            'Cần quyền Administrator',
            'Fleasion cần quyền Administrator để sửa file hosts và cài chứng chỉ.\n\n'
            'Chạy lại với quyền Administrator? (Chọn "No" để chỉ chỉnh sửa FastFlag, proxy sẽ không chạy.)',
        )
        if answer == QMessageBox.StandardButton.Yes and winsys.relaunch_as_admin():
            return 0
        run_proxy = False

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lock = QLockFile(str(CONFIG_DIR / 'fleasion.lock'))
    lock.setStaleLockTime(0)
    if not lock.tryLock(200):
        QMessageBox.information(None, 'Fleasion', 'Fleasion đang chạy rồi (kiểm tra khay hệ thống).')
        return 0

    settings = Settings()
    service = FleasionService(settings) if run_proxy else None
    window = MainWindow(settings, service)

    class Bridge(QObject):
        failed = pyqtSignal(str, str)

    bridge = Bridge()
    bridge.failed.connect(window.show_error)

    if service is not None:
        atexit.register(service.stop)
        app.aboutToQuit.connect(service.stop)

        def start_service() -> None:
            try:
                service.start()
            except ServiceError as exc:
                service.stop()  # dọn dở dang (hosts/proxy) trước khi báo lỗi
                log_buffer.log('Service', f'Khởi động thất bại [{exc.code}]: {exc}')
                service.status.last_error = str(exc)
                bridge.failed.emit('Không khởi động được proxy', str(exc))
            except Exception as exc:
                service.stop()
                log_buffer.log('Service', f'Lỗi không mong đợi: {exc!r}')
                service.status.last_error = str(exc)
                bridge.failed.emit('Lỗi không mong đợi', repr(exc))

        threading.Thread(target=start_service, name='fleasion-start', daemon=True).start()

    window.show()
    code = app.exec()
    lock.unlock()
    return code
