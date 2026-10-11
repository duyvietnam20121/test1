"""Nhật ký đơn giản: ghi file xoay vòng và đẩy dòng mới tới callback (GUI)."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime

from .paths import LOG_FILE, LOGS_DIR

MAX_LOG_FILE_BYTES = 1 * 1024 * 1024
MAX_MEMORY_LINES = 2000


class LogBuffer:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._lines: list[str] = []
        self._listeners: list[Callable[[str], None]] = []

    def add_listener(self, callback: Callable[[str], None]) -> None:
        with self._lock:
            self._listeners.append(callback)

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._lines)

    def log(self, category: str, message: str) -> None:
        now = datetime.now()
        entry = f'[{now:%H:%M:%S}] [{category}] {message}'
        with self._lock:
            self._lines.append(entry)
            del self._lines[:-MAX_MEMORY_LINES]
            listeners = list(self._listeners)
            self._write_file(f'{now:%Y-%m-%d} {entry}\n')
        for callback in listeners:
            try:
                callback(entry)
            except Exception:
                pass

    @staticmethod
    def _write_file(line: str) -> None:
        try:
            LOGS_DIR.mkdir(parents=True, exist_ok=True)
            if LOG_FILE.exists() and LOG_FILE.stat().st_size + len(line) > MAX_LOG_FILE_BYTES:
                rotated = LOG_FILE.with_suffix('.log.1')
                rotated.unlink(missing_ok=True)
                LOG_FILE.replace(rotated)
            with LOG_FILE.open('a', encoding='utf-8') as handle:
                handle.write(line)
        except OSError:
            pass


log_buffer = LogBuffer()
