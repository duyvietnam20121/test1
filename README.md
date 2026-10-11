# Fleasion – bản chỉ FastFlags (Windows)

Bản rút gọn của Fleasion 2.4.0: chỉ giữ phần chỉnh FastFlag. Không còn replacer, cache/scraper, username spoofer, v.v.

## Cách hoạt động
1. Chạy với quyền Administrator.
2. Tạo/dùng lại CA trong `%LOCALAPPDATA%\FleasionNT\proxy_ca`, cài vào kho Root của Windows và `ssl\cacert.pem` của Roblox.
3. Trỏ `clientsettings.roblox.com` và `clientsettingscdn.roblox.com` về `127.0.0.1` (file hosts), proxy cục bộ ghép FastFlag vào phản hồi ClientSettings.
4. Khi thoát, hosts được khôi phục.

`settings.json` và profile của bản Fleasion cũ được dùng lại nguyên vẹn.

## Chạy / build
```
pip install -e .
python -m fleasion
pyinstaller --onefile --noconsole --uac-admin --icon src/fleasion/fleasionlogoHR.ico --add-data "src/fleasion/fleasionlogoHR.ico;fleasion" --paths src --collect-submodules fleasion launcher.py
```

## Sự cố
- Roblox không vào được sau khi app bị tắt đột ngột: chạy `python -m fleasion --cleanup`.
- Gỡ hoàn toàn (hosts + CA): `python -m fleasion --uninstall`.
- Test: `pip install pytest && pytest` (phần Windows chỉ test được logic file, không test registry/certutil).
