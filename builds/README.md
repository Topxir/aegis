# Сборки Aegis (`builds/`)

> ⚠ **Примечание:** артефакты в этой папке — **неаудированный прототип (`v0.1.0-alpha`, unaudited)**. Не используйте их для критически чувствительной переписки до завершения миграции криптоядра по плану [`docs/security-reset/`](../docs/security-reset/).

## 1. 📱 `builds/android-apk/aegis-messenger-release.apk`
- APK для Android 9.0+ (`minSdk 28`, `targetSdk 34`) на базе Jetpack Compose (русский и английский язык `RU / EN`, `FLAG_SECURE`, `excludeFromRecents="true"`, `allowBackup="false"`, инкогнито-клавиатура, `LeakGuard`, без Google Play Services и без разрешений на микрофон/камеру).
- Поддерживает подключение к вашему серверу `aegis-serverd` (`host:port`), `SOCKS5h` прокси, релею и блокировку сети (`Kill Switch`).

## 2. 🖥 `builds/desktop/aegis-desktop.exe` + `builds/desktop/WebView2Loader.dll`
- Нативный десктопный клиент для Windows (`tao 0.37.2` + `wry 0.57.1` поверх системного WebView2, `windows_subsystem = "windows"` — запускается сразу в окне приложения без консоли).
- Навигация WebView ограничена локальным адресом `http://127.0.0.1:<port>`, всплывающие окна, внешние разрешения и DevTools отключены.
- Для запуска держите `WebView2Loader.dll` в одной папке с `aegis-desktop.exe`.

## 3. 🌐 `builds/server/`
- **`aegis-serverd.exe`** — сервер очередей (`--bind=0.0.0.0 --port=8443`, фиксированные блоки `256..16384 B`, проверка `auth_hash` / `read_token`, пересылка `/api/v1/queue/relay` и `/api/v1/queue/relay_poll`).
- **`deploy-static-ip-vps.sh`** и **`docker-compose.yml`** — шаблоны запуска сервера в Docker на Linux VPS.
