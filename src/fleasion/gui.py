"""Giao diện PyQt6: chỉnh FastFlag, profile, nhập/xuất JSON, nhật ký."""

from __future__ import annotations

import json
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QAction, QIcon
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSystemTrayIcon,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .fflags import ProfileManager, Settings, normalize_custom_fflags
from .log import log_buffer
from .paths import ICON_FILE
from .service import FleasionService

SAVE_DEBOUNCE_MS = 500
STATUS_REFRESH_MS = 2000
WARNING_TEXT = (
    'FastFlag sai hoặc không được hỗ trợ có thể làm Roblox lỗi, treo hoặc bị chặn.\n\n'
    'Chỉ dùng flag bạn hiểu rõ. Thay đổi chỉ có hiệu lực khi Fleasion đang chạy '
    '(proxy đang bật) trước khi Roblox khởi động.\n\nTiếp tục bật FastFlag tùy chỉnh?'
)


class PasteJsonDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Dán JSON FastFlag')
        self.resize(520, 380)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel('Dán JSON dạng {"TênFlag": "giá trị", ...}:'))
        self.editor = QPlainTextEdit()
        self.editor.setPlaceholderText('{\n  "DFIntTaskSchedulerTargetFps": "240"\n}')
        layout.addWidget(self.editor)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def text(self) -> str:
        return self.editor.toPlainText()


class ProfilesDialog(QDialog):
    """Quản lý profile; ``loaded`` phát ra dict flag khi người dùng nạp một profile."""

    loaded = pyqtSignal(dict, bool)  # (flags, thay_thế_toàn_bộ)

    def __init__(self, current_flags: dict[str, str], parent=None, manager: ProfileManager | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle('Profile FastFlag')
        self.resize(420, 360)
        self._current = current_flags
        self._manager = manager or ProfileManager()

        layout = QVBoxLayout(self)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(lambda _item: self._load(replace=True))
        layout.addWidget(self.list)

        row = QHBoxLayout()
        for text, handler in (
            ('Lưu hiện tại...', self._save),
            ('Nạp (thay thế)', lambda: self._load(replace=True)),
            ('Nạp (gộp)', lambda: self._load(replace=False)),
            ('Đổi tên...', self._rename),
            ('Xóa', self._delete),
        ):
            button = QPushButton(text)
            button.clicked.connect(handler)
            row.addWidget(button)
        layout.addLayout(row)
        self._refresh()

    def _refresh(self, select: str | None = None) -> None:
        self.list.clear()
        self.list.addItems(self._manager.list_profiles())
        if select:
            for index in range(self.list.count()):
                if self.list.item(index).text() == select:
                    self.list.setCurrentRow(index)

    def _selected(self) -> str | None:
        item = self.list.currentItem()
        if item is None:
            QMessageBox.information(self, 'Profile', 'Hãy chọn một profile trong danh sách.')
            return None
        return item.text()

    def _guard(self, action):
        try:
            return action()
        except (ValueError, OSError) as exc:
            QMessageBox.warning(self, 'Profile', str(exc))
            return None

    def _save(self) -> None:
        name, ok = QInputDialog.getText(self, 'Lưu profile', 'Tên profile:')
        if not ok:
            return
        saved = self._guard(lambda: self._manager.save(name, self._current))
        if saved:
            self._refresh(saved)

    def _load(self, *, replace: bool) -> None:
        name = self._selected()
        if name is None:
            return
        flags = self._guard(lambda: self._manager.load(name))
        if flags is not None:
            self.loaded.emit(flags, replace)
            self.accept()

    def _rename(self) -> None:
        name = self._selected()
        if name is None:
            return
        new_name, ok = QInputDialog.getText(self, 'Đổi tên profile', 'Tên mới:', text=name)
        if ok:
            renamed = self._guard(lambda: self._manager.rename(name, new_name))
            if renamed:
                self._refresh(renamed)

    def _delete(self) -> None:
        name = self._selected()
        if name is None:
            return
        if QMessageBox.question(self, 'Xóa profile', f'Xóa profile "{name}"?') == QMessageBox.StandardButton.Yes:
            self._guard(lambda: self._manager.delete(name))
            self._refresh()


class MainWindow(QMainWindow):
    """Cửa sổ chính. Mọi thay đổi được tự động lưu và áp dụng sau một nhịp ngắn."""

    log_line = pyqtSignal(str)

    def __init__(self, settings: Settings, service: FleasionService | None) -> None:
        super().__init__()
        self._settings = settings
        self._service = service
        self._loading = False
        self._tray: QSystemTrayIcon | None = None
        self._really_quit = False

        self.setWindowTitle('Fleasion - FastFlags')
        self.resize(760, 560)
        if ICON_FILE.exists():
            self.setWindowIcon(QIcon(str(ICON_FILE)))

        tabs = QTabWidget()
        tabs.addTab(self._build_flags_tab(), 'FastFlags')
        tabs.addTab(self._build_log_tab(), 'Nhật ký')
        self.setCentralWidget(tabs)

        self._save_timer = QTimer(self)
        self._save_timer.setSingleShot(True)
        self._save_timer.setInterval(SAVE_DEBOUNCE_MS)
        self._save_timer.timeout.connect(self._save_now)

        self._status_timer = QTimer(self)
        self._status_timer.setInterval(STATUS_REFRESH_MS)
        self._status_timer.timeout.connect(self._refresh_status)
        self._status_timer.start()

        self.log_line.connect(self._append_log)
        for line in log_buffer.snapshot():
            self._append_log(line)
        log_buffer.add_listener(self.log_line.emit)

        self._populate(self._settings.flags, set(self._settings.disabled))
        self._refresh_status()
        self._setup_tray()

    # -- dựng giao diện -------------------------------------------------

    def _build_flags_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.enable_box = QCheckBox('Bật FastFlag tùy chỉnh')
        self.enable_box.setChecked(self._settings.enabled)
        self.enable_box.toggled.connect(self._on_enable_toggled)
        layout.addWidget(self.enable_box)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText('Lọc theo tên hoặc giá trị...')
        self.filter_edit.setClearButtonEnabled(True)
        self.filter_edit.textChanged.connect(self._apply_filter)
        layout.addWidget(self.filter_edit)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(['Tên FastFlag', 'Giá trị'])
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
            | QAbstractItemView.EditTrigger.AnyKeyPressed
        )
        self.table.itemChanged.connect(self._on_item_changed)
        layout.addWidget(self.table, 1)
        hint = QLabel('Tick ô bên trái tên để bật/tắt từng flag mà không cần xóa. Nhấp đúp để sửa.')
        hint.setStyleSheet('color: gray;')
        layout.addWidget(hint)

        row = QHBoxLayout()
        for text, handler in (
            ('Thêm', self._add_row),
            ('Xóa đã chọn', self._delete_selected),
            ('Dán JSON...', self._paste_json),
            ('Nhập file...', self._import_file),
            ('Xuất file...', self._export_file),
            ('Profile...', self._open_profiles),
        ):
            button = QPushButton(text)
            button.clicked.connect(handler)
            row.addWidget(button)
        layout.addLayout(row)
        return page

    def _build_log_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(2000)
        layout.addWidget(self.log_view)
        return page

    def _setup_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        tray = QSystemTrayIcon(self.windowIcon(), self)
        tray.setToolTip('Fleasion - FastFlags')
        menu = QMenu()
        show = QAction('Mở Fleasion', menu)
        show.triggered.connect(self._show_window)
        quit_action = QAction('Thoát', menu)
        quit_action.triggered.connect(self.quit_app)
        menu.addAction(show)
        menu.addAction(quit_action)
        tray.setContextMenu(menu)
        tray.activated.connect(
            lambda reason: self._show_window()
            if reason == QSystemTrayIcon.ActivationReason.Trigger
            else None
        )
        tray.show()
        self._tray = tray

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # -- bảng flag ------------------------------------------------------

    def _populate(self, flags: dict[str, str], disabled: set[str]) -> None:
        self._loading = True
        try:
            self.table.setRowCount(0)
            for name, value in flags.items():
                self._append_row(name, value, name not in disabled)
        finally:
            self._loading = False
        self._apply_filter()

    def _append_row(self, name: str, value: str, enabled: bool = True) -> int:
        row = self.table.rowCount()
        self.table.insertRow(row)
        name_item = QTableWidgetItem(name)
        name_item.setFlags(name_item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        name_item.setCheckState(Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked)
        self.table.setItem(row, 0, name_item)
        self.table.setItem(row, 1, QTableWidgetItem(value))
        return row

    def _collect(self) -> tuple[dict[str, str], list[str]]:
        flags: dict[str, str] = {}
        disabled: list[str] = []
        for row in range(self.table.rowCount()):
            name_item, value_item = self.table.item(row, 0), self.table.item(row, 1)
            name = (name_item.text() if name_item else '').strip()
            if not name:
                continue
            flags[name] = value_item.text() if value_item else ''
            if name_item.checkState() != Qt.CheckState.Checked:
                disabled.append(name)
        return flags, disabled

    def _apply_filter(self) -> None:
        needle = self.filter_edit.text().strip().lower()
        for row in range(self.table.rowCount()):
            name_item, value_item = self.table.item(row, 0), self.table.item(row, 1)
            haystack = f'{name_item.text() if name_item else ""} {value_item.text() if value_item else ""}'.lower()
            self.table.setRowHidden(row, bool(needle) and needle not in haystack)

    def _on_item_changed(self, _item: QTableWidgetItem) -> None:
        if not self._loading:
            self._schedule_save()

    def _add_row(self) -> None:
        self.filter_edit.clear()
        self._loading = True
        try:
            row = self._append_row('', '')
        finally:
            self._loading = False
        self.table.setCurrentCell(row, 0)
        self.table.scrollToItem(self.table.item(row, 0))
        self.table.editItem(self.table.item(row, 0))

    def _delete_selected(self) -> None:
        rows = sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True)
        if not rows:
            return
        for row in rows:
            self.table.removeRow(row)
        self._schedule_save()

    # -- nhập/xuất --------------------------------------------------------

    def _merge_flags(self, incoming: dict[str, str], *, replace: bool) -> None:
        """Nạp flag vào bảng. ``replace`` thay toàn bộ; ngược lại gộp (flag trùng tên bị ghi đè)."""
        if replace:
            self._populate(dict(incoming), set())
        else:
            current, disabled = self._collect()
            # Flag vừa nạp luôn ở trạng thái bật; flag cũ giữ nguyên trạng thái.
            self._populate({**current, **incoming}, set(disabled) - set(incoming))
        self._schedule_save()

    def _parse_json_text(self, text: str, source: str) -> dict[str, str] | None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, 'JSON không hợp lệ', f'{source}: {exc.msg} (dòng {exc.lineno}, cột {exc.colno})')
            return None
        if not isinstance(payload, dict):
            QMessageBox.warning(self, 'JSON không hợp lệ', f'{source}: cần một object {{"tên": "giá trị"}}.')
            return None
        flags = normalize_custom_fflags(payload)
        skipped = len(payload) - len(flags)
        if skipped:
            QMessageBox.information(
                self, 'Đã bỏ qua', f'Bỏ qua {skipped} mục có giá trị không phải chuỗi/số/boolean.'
            )
        return flags

    def _paste_json(self) -> None:
        dialog = PasteJsonDialog(self)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.text().strip():
            flags = self._parse_json_text(dialog.text(), 'JSON đã dán')
            if flags is not None:
                self._merge_flags(flags, replace=False)

    def _import_file(self) -> None:
        filename, _ = QFileDialog.getOpenFileName(self, 'Nhập FastFlag', '', 'JSON (*.json);;Tất cả (*)')
        if not filename:
            return
        try:
            text = Path(filename).read_text(encoding='utf-8-sig')
        except (OSError, UnicodeDecodeError) as exc:
            QMessageBox.warning(self, 'Không đọc được file', str(exc))
            return
        flags = self._parse_json_text(text, Path(filename).name)
        if flags is not None:
            self._merge_flags(flags, replace=False)

    def _export_file(self) -> None:
        flags, _disabled = self._collect()
        filename, _ = QFileDialog.getSaveFileName(self, 'Xuất FastFlag', 'fastflags.json', 'JSON (*.json)')
        if not filename:
            return
        try:
            Path(filename).write_text(json.dumps(flags, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        except OSError as exc:
            QMessageBox.warning(self, 'Không ghi được file', str(exc))

    def _open_profiles(self) -> None:
        flags, _disabled = self._collect()
        dialog = ProfilesDialog(flags, self)
        dialog.loaded.connect(lambda loaded, replace: self._merge_flags(loaded, replace=replace))
        dialog.exec()

    # -- lưu & áp dụng ----------------------------------------------------

    def _schedule_save(self) -> None:
        self._save_timer.start()

    def _save_now(self) -> None:
        flags, disabled = self._collect()
        self._settings.flags = flags
        self._settings.disabled = disabled
        self._settings.enabled = self.enable_box.isChecked()
        try:
            self._settings.save()
        except OSError as exc:
            QMessageBox.warning(self, 'Không lưu được', str(exc))
            return
        if self._service is not None:
            self._service.apply_settings()
        log_buffer.log('FastFlags', f'Đã lưu {len(flags)} flag ({len(disabled)} đang tắt)')

    def _on_enable_toggled(self, checked: bool) -> None:
        if checked and not self._settings.warning_accepted:
            answer = QMessageBox.warning(
                self,
                'Cảnh báo FastFlag',
                WARNING_TEXT,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if answer != QMessageBox.StandardButton.Yes:
                self.enable_box.blockSignals(True)
                self.enable_box.setChecked(False)
                self.enable_box.blockSignals(False)
                return
            self._settings.warning_accepted = True
        self._save_timer.stop()
        self._save_now()

    # -- trạng thái & nhật ký -------------------------------------------

    def _refresh_status(self) -> None:
        service = self._service
        if service is None:
            self.status_label.setText('⚠ Chế độ chỉ chỉnh sửa: chưa có quyền Administrator nên proxy không chạy.')
            return
        status = service.status
        if not status.running:
            text = f'⏸ Proxy chưa chạy. {status.last_error}'.strip()
        else:
            parts = ['✅ Proxy đang chạy']
            parts.append('hosts đã chuyển hướng' if status.hosts_redirected else 'hosts CHƯA chuyển hướng')
            if status.roblox_installs:
                parts.append(f'CA Roblox: {status.roblox_patched}/{status.roblox_installs} bản')
            else:
                parts.append('chưa thấy bản Roblox nào')
            if not status.root_ca_trusted:
                parts.append('⚠ CA chưa vào kho Root Windows')
            if status.conflicts:
                parts.append('⚠ hosts có dòng xung đột (xem Nhật ký)')
            text = ' · '.join(parts)
            if status.last_error:
                text += f'\n⚠ {status.last_error}'
        self.status_label.setText(text)

    def _append_log(self, line: str) -> None:
        self.log_view.appendPlainText(line)

    def show_error(self, title: str, message: str) -> None:
        QMessageBox.critical(self, title, message)
        self._refresh_status()

    # -- thoát ------------------------------------------------------------

    def quit_app(self) -> None:
        self._really_quit = True
        self.close()
        QApplication.quit()

    def closeEvent(self, event) -> None:  # noqa: N802 (tên do Qt quy định)
        if self._save_timer.isActive():
            self._save_timer.stop()
            self._save_now()
        if self._tray is not None and not self._really_quit:
            event.ignore()
            self.hide()
            if not self._settings.enabled:
                return
            self._tray.showMessage(
                'Fleasion', 'Vẫn đang chạy ở khay hệ thống. Bấm chuột phải biểu tượng để thoát.',
                QSystemTrayIcon.MessageIcon.Information, 3000,
            )
            return
        event.accept()
