# Aegis — Мессенджер (Unaudited Prototype `v0.1.0-alpha`)

> ⚠ **Статус безопасности:** текущие сборки в [`builds/`](builds/) представляют собой **неаудированный прототип (`unaudited alpha`)**. Встроенные в прототип криптографические и транспортные примитивы написаны вручную для демонстрации архитектуры и **не проходили внешний криптоаудит** (см. [`docs/BUGS.md`](docs/BUGS.md) `B-0093`..`B-0100` и план перехода на `libsignal` / `OpenMLS` / `rustls` / `arti` / `SQLCipher` в [`docs/security-reset/`](docs/security-reset/)).

---

## 📦 Сборки в папке [`builds/`](builds/)

1. **📱 Android APK — [`builds/android-apk/aegis-messenger-release.apk`](builds/android-apk/aegis-messenger-release.apk)**
   - Клиент на Jetpack Compose (русский и английский интерфейс, список чатов, локальный поиск, PIN-блокировка чата, проверка чувствительных данных `LeakGuard`, `FLAG_SECURE`, `excludeFromRecents="true"`, `allowBackup="false"`, без Google Play Services и без разрешений на микрофон/камеру).
   - Поддерживает обмен капсулами с сервером `aegis-serverd` напрямую по `host:port`, через `SOCKS5h` прокси или через релей.

2. **🖥 ПК-клиент (Windows) — [`builds/desktop/aegis-desktop.exe`](builds/desktop/aegis-desktop.exe) + [`builds/desktop/WebView2Loader.dll`](builds/desktop/WebView2Loader.dll)**
   - Нативное графическое окно Windows (`tao` + `wry` поверх WebView2, без запуска окна консоли).
   - Поддерживает русский и английский язык (`RU / EN`), локальные профили, подключение к серверу `aegis-serverd` (`host:port`), `SOCKS5h` прокси, релей, блокировку сети (`Kill Switch`), PIN-код чата и таймер сообщений.

3. **🌐 Сервер очередей и скрытый туннель — [`builds/server/`](builds/server/)**
   - **`aegis-serverd.exe`** — демон сервера очередей (`--bind=127.0.0.1 --port=8443`, фиксированные корзины `256..16384 B`, проверка `auth_hash` / `read_token`, эндпоинты пересылки `/api/v1/queue/relay` и `/api/v1/queue/relay_poll`).
   - **`start-hidden-server.bat`** — запускает `aegis-serverd.exe` только на локальном интерфейсе `127.0.0.1:8443` и пробрасывает его через исходящий Anycast-туннель (`cloudflared`), благодаря чему реальный IP вашего ПК никогда не раскрывается, а внешний Anycast IP (`104.21.53.92:80` / `172.67.211.53:80` / `freeoasis.space:80`) остаётся статическим даже после выключения и повторного включения сервера.
   - **`deploy-static-ip-vps.sh`** и **`docker-compose.yml`** — скрипты развёртывания серверного контейнера на Linux VPS.

---

## Навигация по документации

- [`AGENTS.md`](AGENTS.md) — правила разработки и структура модулей
- [`docs/security-reset/`](docs/security-reset/) — актуальная спецификация безопасности v2 (`THREAT_MODEL_V2.md`, `PROTOCOL_V2.md`, `ARCHITECTURE_V2.md`, `ROADMAP_V2.md`)
- [`docs/STATE.md`](docs/STATE.md) — текущее состояние модулей
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — журнал архитектурных решений (`D-0001`..`D-0028`)
- [`docs/BUGS.md`](docs/BUGS.md) — реестр найденных и открытых проблем (`B-0001`..`B-0106`)
