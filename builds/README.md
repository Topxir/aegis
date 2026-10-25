# Глобальные релизные сборки Aegis (Pure Chat Fortress // Phantom Monolith)

Эта папка (`builds/`) содержит только ключевые финальные релизные артефакты проекта **Aegis v0.1.0** (`D-0021`, `D-0022`):

## 1. 📱 `builds/android-apk/aegis-messenger-release.apk`
- Подписанный релизный APK для Android 9.0+ (авторский интерфейс **«Aegis Phantom Monolith»**, `FLAG_SECURE`, `excludeFromRecents="true"`, Android StrongBox Keystore, инкогнито-клавиатура, маскировка под калькулятор, **0 разрешений на микрофон и камеру**).
- Вшиты 3 стартовых анонимных сервера со статическим IP (`185.220.101.42:8443 ✓✓`, `91.108.56.110:8443 ✓✓`, `193.163.125.18:8443 ✓`), работающие напрямую без обязательного Tor, плюс 1-клик ввод своего Static IP и опциональный Tor `.onion`.

## 2. 🖥 `builds/desktop/aegis-desktop.exe`
- Автономный бинарный клиент Aegis для ПК (Windows) с локальным защищённым GUI «Phantom Monolith» (`aegis-desktop.exe --gui --port 7878`) и встроенным полным автотестом (`aegis-desktop.exe --self-test`).

## 3. 🌐 `builds/server/`
- **`aegis-serverd.exe`** — бинарный демон сервера федерации (`--bind=0.0.0.0 --port=8443`, `Zero-IP-Logs`, односторонние очереди `256..16384 B`, constant-shape `OPAQUE` 1024 B, адаптивный PoW и портал `SupporterPass`).
- **`deploy-static-ip-vps.sh`** и **`docker-compose.yml`** — однокомандное развёртывание анонимного стартового узла на любом Linux VPS со статическим IP (`logging: driver: "none"`, `read_only: true`, `cap_drop: ALL`).
