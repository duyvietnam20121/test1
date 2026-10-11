"""Đường dẫn và hằng số của ứng dụng (chỉ hỗ trợ Windows).

Thư mục cấu hình giữ nguyên ``FleasionNT`` để dùng lại ``settings.json``,
CA và các profile FastFlag của bản Fleasion gốc.
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = 'Fleasion'

LOCAL_APPDATA = Path(os.environ.get('LOCALAPPDATA') or (Path.home() / 'AppData' / 'Local'))

# FLEASION_CONFIG_DIR chỉ dùng cho test / debug.
CONFIG_DIR = Path(os.environ.get('FLEASION_CONFIG_DIR') or (LOCAL_APPDATA / 'FleasionNT'))
CONFIG_FILE = CONFIG_DIR / 'settings.json'
PROFILES_DIR = CONFIG_DIR / 'FastFlagProfiles'
PROXY_CA_DIR = CONFIG_DIR / 'proxy_ca'
LOGS_DIR = CONFIG_DIR / 'logs'
LOG_FILE = LOGS_DIR / 'fleasion.log'

# Cache cờ của Roblox Player (được ghi trước khi Player gọi mạng lần đầu).
FLAG_CACHE_PATH = LOCAL_APPDATA / 'Temp' / 'Roblox' / 'cache' / 'flag_cache.dat'

HOSTS_FILE = (
    Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'
)

ROBLOX_PLAYER_EXE = 'RobloxPlayerBeta.exe'
ICON_FILE = Path(__file__).with_name('fleasionlogoHR.ico')
