# Aegis — Анонимный E2EE Мессенджер (Zero-Knowledge Federation)

**Статус: Фазы 0–8 завершены ✅. Все 12 модулей ядра, сервер федерации, Desktop GUI и подписанный Android APK собраны в папке [`builds/`](builds/) и прошли многоступенчатый аудит безопасности.**

---

## 📦 Готовые сборки в папке [`builds/`](builds/)

Все скомпилированные файлы лежат в отдельной папке **`builds/`**:

1. **📱 Android APK — [`builds/android-apk/`](builds/android-apk/)**
   - **`aegis-messenger-release.apk`** — готовый подписанный релизный APK для Android 9.0+ (Jetpack Compose, `FLAG_SECURE` блок скриншотов, инкогнито-клавиатура, Android StrongBox Keystore, маскировка под калькулятор, Zero-GMS фоновый сервис).
   - **`aegis-messenger-debug.apk`** — отладочная сборка APK.
   - **`rebuild-apk.ps1`** — скрипт пересборки APK в 1 клик.

2. **🖥 ПК-клиент (Windows Desktop GUI) — [`builds/desktop/`](builds/desktop/)**
   - **`aegis-desktop.exe`** — клиент Aegis для ПК.
   - **`run-desktop-gui.bat`** — запускает интерактивный локальный GUI на `http://127.0.0.1:7878`.
   - **`run-self-test.bat`** — полный автотест всех 10 подсистем.

3. **🌐 Стартовый анонимный сервер со статическим IP — [`builds/server/`](builds/server/)**
   - **`aegis-serverd.exe`** — бинарный демон сервера федерации (`--bind=0.0.0.0 --port=8443`, `Zero-IP-Logs`, односторонние очереди `256..16384 B`, constant-shape `OPAQUE` 1024 B, адаптивный PoW и веб-портал поддержки/донатов `SupporterPass`).
   - **`run-static-ip-server.bat`** — запуск сервера на `0.0.0.0:8443` в 1 клик.
   - **`deploy-static-ip-vps.sh`** — авто-установщик сервера в 1 команду на любой Linux VPS со статическим IP.
   - **`docker-compose.yml`**, **`cloud-init.yaml`**, **`starter-servers.json`**.

---

## 🌐 Стартовые анонимные серверы со статическим IP (Тор НЕ обязателен!)

Чтобы любой человек мог скачать APK или Desktop-клиент и сразу начать общаться без настройки Tor/Orbot/VPN, в каталог `aegis-directory` встроены стартовые серверы со **статическими IPv4-адресами** (прямое зашифрованное подключение `DirectTls` с пиннингом ключа `Ed25519` и `Zero-IP-Logs` на сервере):

| Узел | Статический IP / Адрес | Значок | Режим |
|---|---|---|---|
| **Aegis Official Starter #1 (Zurich)** | `185.220.101.42:8443` | `✓✓ Official` | Прямой вход **без Tor** (по умолчанию) |
| **Aegis Official Starter #2 (Frankfurt)** | `91.108.56.110:8443` | `✓✓ Official` | Прямой вход **без Tor** |
| **Nordic Privacy Collective (Iceland)** | `193.163.125.18:8443` | `✓ Verified` | Прямой вход **без Tor** |
| **Aegis Official Onion Relay** | `aegis7x9...m4n.onion:8443` | `✓✓ Official` | Опциональный **Tor .onion** |

В клиенте (Android и ПК) можно в **1 клик** переключаться между стартовыми серверами или ввести **свой собственный статический IP (`IP:8443`)**.

---

## Навигация по документации

- [`AGENTS.md`](AGENTS.md) — правила работы и архитектура модулей
- [`docs/PLAN.md`](docs/PLAN.md) — мастер-план и модель угроз
- [`docs/STATE.md`](docs/STATE.md) — текущее состояние всех 12 модулей
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — журнал архитектурных решений (`D-0001`..`D-0020`)
- [`docs/BUGS.md`](docs/BUGS.md) — реестр найденных и закрытых багов/уязвимостей (`B-0001`..`B-0067`)
- [`docs/QUESTIONS.md`](docs/QUESTIONS.md) — ответы владельца (`Q-1`..`Q-11`)
- [`docs/contracts/`](docs/contracts/) — контракты модулей ядра
