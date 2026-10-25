# Состояние проекта

Обновляется после каждой задачи. Легенда: ✅ готово · 🔧 в работе · ❌ не начато · ⚠ проблема

Текущая фаза: **10. Глобальная международная сетевая доставка капсул (Cross-Border Live TCP & SOCKS5h/Tor Networking, T-0014 ✅), Чистая чат-крепость без звонков (D-0021), дизайн «Phantom Monolith» (D-0022) и глобальные релизные сборки `builds/`**
Обновлено: 2026-10-25

| Модуль | Статус | Заметки |
|---|---|---|
| aegis-crypto | ✅ | SHA-256 (с очисткой стека `w`/`tail`/`state`), HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 AEAD (RFC 8439), гибридный PQXDH, `RatchetSession` (привязка 40-байтного `RatchetHeader` к AEAD AAD, `Drop` очистка), `ZeroizingBuffer` (очистка всей ёмкости `0..capacity()`), `constant_time_eq` без утечки длины, `solve_pow`; исправлены `B-0011`, `B-0020`, `B-0032`..`B-0034`, `B-0056`, `B-0068`, `B-0079` |
| aegis-identity | ✅ | OPAQUE (`derive_login_id`, `OpaqueAccountEnvelope`, `OpaqueClientSession` с уникальным HMAC-nonce и `Drop`), строгие пароли D-0006 с очисткой `0..capacity()`, 24 слова (`RecoveryPhrase`), мультиаккаунт 3+`SupporterPass` D-0010, `PinGuard` + Duress, `AppDisguiseConfig` (`Drop` и константно-временной `check_calculator_unlock`), `ChatPinLock`; исправлены `B-0007`..`B-0010`, `B-0021`, `B-0035`..`B-0038`, `B-0057`, `B-0069`, `B-0079` |
| aegis-storage | ✅ | `EncryptedVaultDb` (`Drop` с автоматическим `crypto_wipe` на БД и всех записях `StoredContact`/`StoredMessage`/`EncryptedNote`, полное редактирование `Debug`, затирание `plaintext_body` при `purge_expired_messages`, проверка изоляции `send_queue_id != recv_queue_id`, экспорт/импорт `AEGISBAK`); исправлены `B-0012`, `B-0022`, `B-0039`, `B-0040`, `B-0058`, `B-0070`, `B-0079` |
| aegis-protocol | ✅ | Чистая чат-крепость без голосовых/видео звонков (`D-0021`), 1:1 `SealedSenderEnvelope` и групповой `GroupChatSession` (Pad-Before-Encrypt внутри AEAD без открытой длины на проводе), `LeakGuard` (Luhn + CVV/MM/YY + телефоны + email + `CryptoSeedOrPrivateKey` `0x`/WIF/`xprv`/PEM + ASCII/Unicode ники), `strip_media_metadata` (белый список чанков PNG против Apple `iDOT`/`pHYs`/`iCCP` + очистка `APP0..APP15`/`JPG0..JPG13`/`COM` в JPEG), блокировка hex-IP SSRF (`0xa9.0xfe.0xa9.0xfe`); исправлены `B-0001`..`B-0006`, `B-0023`, `B-0024`, `B-0041`..`B-0043`, `B-0059`, `B-0071`, `B-0080` |
| aegis-transport | ✅ | `Network Anonymity Shield` (безусловная блокировка при утечке туннеля), `IsolatedCircuitTag` и `derive_circuit_isolation_token`, `CoverTrafficScheduler` (256 B криптографический поток HMAC-SHA256 с независимым `schedule_step`), блокировка hex-IP SSRF; исправлены `B-0013`, `B-0044`, `B-0045`, `B-0060`, `B-0072`, `B-0081` |
| aegis-server | ✅ | Zero-knowledge сервер федерации (`FederationServerState`, криптографический HKDF-синтез 1024 B OPAQUE-записей, удаление метаданных `active_queues`/`buffered_frames` из HTTP-ответов `/health` и `/api/v1/queue/send`), демон `aegis-serverd` (строгий HTTP-парсер, буфер 32 КБ, CSP/No-Store заголовки); исправлены `B-0015`, `B-0025`, `B-0048`, `B-0049`, `B-0064`, `B-0074`, `B-0081` |
| aegis-directory | ✅ | Встроенный каталог серверов `BuiltInDirectory` со стартовыми статическими IPv4 узлами без обязательного Tor (`185.220.101.42:8443 ✓✓`, `91.108.56.110:8443 ✓✓`, `193.163.125.18:8443 ✓`), сверкой `static_ipv4 == host`, согласованностью бейджей и защитой от hex-IP/onion спуфинга; исправлены `B-0016`, `B-0026`, `B-0062`, `B-0075`, `B-0081` |
| aegis-launcher | ✅ | Мастер запуска своего сервера в 1 клик (`generate_static_ip_vps_script`, `generate_docker_compose` с `logging: driver: "none"`, `generate_cloud_init_script` с `ufw allow 22/tcp`, `generate_torrc_hidden_service` с `HiddenServiceSingleHopMode 0`); исправлены `B-0017`, `B-0027`, `B-0063`, `B-0075`, `B-0081` |
| aegis-plugins | ✅ | Магазин тем (`BuiltInThemes`, `ThemePack`, включая `Phantom Monolith` `#05080F`/`#00F5B8`, `Cyber Lazulite` и `CalculatorStealth`), песочница ботов и мостов (`BotBridgeDescriptor` с защитой от hex/octal/private/localhost SSRF); исправлены `B-0018`, `B-0028`, `B-0065`, `B-0076`, `B-0081` |
| aegis-ffi | ✅ | Единый фасад `AegisClientCore` (без звонков `D-0021`, мультиаккаунтный `LeakGuard`, `trigger_panic_wipe`, реэкспорт `SealedSenderEnvelope`) + сквозной Red-Team аудит-сьют `tests/red_team_anonymity_audit.rs`; исправлены `B-0019`, `B-0029`, `B-0076`, `B-0082` |
| aegis-ui-android | ✅ | Android-клиент «Aegis Phantom Monolith» и глобальный релизный APK (`builds/android-apk/aegis-messenger-release.apk`, **0 разрешений на микрофон и камеру**, `FLAG_SECURE`, `excludeFromRecents="true"`, StrongBox Keystore, лимит попыток PIN); исправлены `B-0031`, `B-0052`..`B-0055`, `B-0067`, `B-0078`, `B-0082` |
| aegis-ui-desktop | ✅ | Desktop-клиент «Aegis Phantom Monolith» (`builds/desktop/aegis-desktop.exe`, капсулы `SEALED CAPSULE`, матрица маршрута, защита `127.0.0.1:7878` от CSRF и DNS Rebinding, 0 звонков); исправлены `B-0030`, `B-0050`, `B-0051`, `B-0066`, `B-0077`, `B-0082` |

## Сделано
- Утверждены архитектурные решения `D-0001`..`D-0022` в `docs/DECISIONS.md`
- ✅ Выполнены задачи **T-0001..T-0012** (Фазы 0–8+)
- ✅ Выполнена задача **T-0013** (Фаза 9 — Чистая чат-крепость без звонков, анти-правительственный хакатон-аудит, уникальный дизайн «Phantom Monolith», Clean-Room IP проверка и очистка `builds/`):
  - Полностью удалены звонки (`aegis-calls`, кнопки/оверлеи звонков, разрешения `RECORD_AUDIO` и `CAMERA` в `AndroidManifest.xml`).
  - Закрыты 82 находки аудита (`B-0001`..`B-0082` в `docs/BUGS.md`), все **96 автотестов** чистой чат-крепости проходят без ошибок.
  - В `builds/` оставлены только самые важные глобальные релизные сборки (`aegis-messenger-release.apk`, `aegis-desktop.exe`, `aegis-serverd.exe`, `deploy-static-ip-vps.sh`, `docker-compose.yml`, `SHA256SUMS.txt`, `README.md`).

## В работе
- Нет активных задач

## Блокеры
- Нет активных блокеров
