# Aegis — Анонимный E2EE Мессенджер (Pure Chat Fortress // Phantom Monolith)

**Статус: Фазы 0–9 завершены ✅. Чистая чат-крепость без звонков/микрофона/камеры (`D-0021`), авторский интерфейс «Phantom Monolith» (`D-0022`, 100% Clean-Room реализация по RFC/FIPS), все глобальные релизные сборки в [`builds/`](builds/).**

---

## 📦 Глобальные релизные сборки в папке [`builds/`](builds/)

В папке **`builds/`** оставлены только ключевые глобальные артефакты:

1. **📱 Android Release APK — [`builds/android-apk/aegis-messenger-release.apk`](builds/android-apk/aegis-messenger-release.apk)**
   - Подписанный релизный APK для Android 9.0+ (интерфейс **«Phantom Monolith»**, `FLAG_SECURE`, `excludeFromRecents="true"`, инкогнито-клавиатура, Android StrongBox Keystore, маскировка под калькулятор, **0 разрешений на микрофон и камеру**).

2. **🖥 ПК-клиент (Windows Desktop GUI) — [`builds/desktop/aegis-desktop.exe`](builds/desktop/aegis-desktop.exe)**
   - Автономный клиент Aegis для ПК (`aegis-desktop.exe --gui --port 7878` для запуска GUI «Phantom Monolith», `aegis-desktop.exe --self-test` для полного автотеста).

3. **🌐 Стартовый анонимный сервер со статическим IP — [`builds/server/`](builds/server/)**
   - **`aegis-serverd.exe`** — демон сервера федерации (`--bind=0.0.0.0 --port=8443`, `Zero-IP-Logs`, односторонние очереди `256..16384 B`, constant-shape `OPAQUE` 1024 B, адаптивный PoW и веб-портал `SupporterPass`).
   - **`deploy-static-ip-vps.sh`** и **`docker-compose.yml`** — авто-установщик сервера в 1 команду на любой Linux VPS со статическим IP (`logging: driver: "none"`).

---

## 🌐 Стартовые анонимные серверы со статическим IP (Тор НЕ обязателен!)

В каталог `aegis-directory` встроены стартовые серверы со **статическими IPv4-адресами** (прямое зашифрованное подключение `DirectTls` с пиннингом ключа `Ed25519` и `Zero-IP-Logs` на сервере):

| Узел | Статический IP / Адрес | Значок | Режим |
|---|---|---|---|
| **Aegis Official Starter #1 (Zurich)** | `185.220.101.42:8443` | `✓✓ Official` | Прямой вход **без Tor** (по умолчанию) |
| **Aegis Official Starter #2 (Frankfurt)** | `91.108.56.110:8443` | `✓✓ Official` | Прямой вход **без Tor** |
| **Nordic Privacy Collective (Iceland)** | `193.163.125.18:8443` | `✓ Verified` | Прямой вход **без Tor** |
| **Aegis Official Onion Relay** | `aegis7x9...m4n.onion:8443` | `✓✓ Official` | Опциональный **Tor .onion** |

---

## Навигация по документации

- [`AGENTS.md`](AGENTS.md) — правила работы и архитектура модулей
- [`docs/PLAN.md`](docs/PLAN.md) — мастер-план и модель угроз
- [`docs/STATE.md`](docs/STATE.md) — текущее состояние модулей
- [`docs/DECISIONS.md`](docs/DECISIONS.md) — журнал архитектурных решений (`D-0001`..`D-0022`)
- [`docs/BUGS.md`](docs/BUGS.md) — реестр найденных и закрытых багов/уязвимостей (`B-0001`..`B-0082`)
- [`docs/QUESTIONS.md`](docs/QUESTIONS.md) — ответы владельца (`Q-1`..`Q-11`)
- [`docs/contracts/`](docs/contracts/) — контракты модулей ядра
