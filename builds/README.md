# Глобальные релизные сборки Aegis

Эта папка (`builds/`) содержит актуальные релизные артефакты **Aegis v0.1.0** (`D-0021`..`D-0028`, `T-0018`):

## 1. 📱 `builds/android-apk/aegis-messenger-release.apk`
- Подписанный релизный APK для Android 9.0+ (`minSdk 28`, `targetSdk 34`): чистый тёмный мессенджер-интерфейс (список чатов, пузыри сообщений, нижняя навигация `Чаты / Серверы / Профиль`), `FLAG_SECURE`, `excludeFromRecents="true"`, `allowBackup="false"`, Android StrongBox Keystore, инкогнито-клавиатура, маскировка под калькулятор, LeakGuard, сверка 60-значного Safety Number и **0 разрешений на микрофон и камеру**.
- Поддерживает прямое подключение по IP/домену, SOCKS5h/Tor с изоляцией потоков и слепой релей (`Zero-Metadata Blind Relay`).

## 2. 🖥 `builds/desktop/aegis-desktop.exe` + `builds/desktop/WebView2Loader.dll`
- Нативный десктопный клиент Aegis для Windows (`tao 0.37.2` + `wry 0.57.1` поверх системного WebView2): открывается в собственном окне приложения (при недоступности WebView2 автоматически переключается на системный браузер).
- Навигация жёстко ограничена локальным адресом `http://127.0.0.1:<port>`, новые окна (`NewWindowResponse::Deny`), внешние разрешения (`PermissionResponse::Deny`), DevTools, контекстное меню и drag-and-drop отключены, форма входа отправляется через `POST` (`application/x-www-form-urlencoded`).
- Включает полный самотест всех 10 подсистем: `aegis-desktop.exe --self-test`.

## 3. 🌐 `builds/server/`
- **`aegis-serverd.exe`** — демон сервера федерации (`--bind=0.0.0.0 --port=8443`, `Zero-IP-Logs`, односторонние очереди `256..16384 B` с проверкой `auth_hash` / `read_token`, слепые релеи `/api/v1/queue/relay` и `/api/v1/queue/relay_poll`, constant-shape `OPAQUE` 1024 B, адаптивный PoW и портал `SupporterPass`).
- **`deploy-static-ip-vps.sh`** и **`docker-compose.yml`** — однокомандное развёртывание узла на Linux VPS (`umask 077`, CSPRNG `AEGIS_BLINDING_SALT_HEX`, `logging: driver: "none"`, `read_only: true`, `cap_drop: ALL`).
