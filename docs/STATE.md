# Состояние проекта

Обновляется после каждой задачи. Легенда: ✅ готово · 🔧 в работе · ❌ не начато · ⚠ проблема

Текущая фаза: **13. Security Reset (T-0017, rev.2) — документы утверждены; Phase 0 (ADR) в работе; код не меняется.**
Обновлено: 2026-10-30

> ⚠ Статусы модулей ниже описывают старый прототип T-0016. Они **не**
> являются доказательством безопасности: ядро самописное, TLS/Tor/MLS/PQXDH
> отсутствуют. Актуальная модель — `docs/security-reset/` (D-0024, D-0025).

| Модуль | Статус | Заметки |
|---|---|---|
| aegis-crypto | ✅ | SHA-256 (с очисткой стека `w`/`tail`/`state`/`a..h`), HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 AEAD (RFC 8439, насыщение счётчика и очистка `mac_data`), гибридный PQXDH, `RatchetSession` (привязка 40-байтного `RatchetHeader` к AEAD AAD, запрет частичного DH-шага `||`, `Drop` очистка), `ZeroizingBuffer` (`0..capacity()`), `constant_time_eq`, `solve_pow`; исправлены `B-0011`, `B-0020`, `B-0032`..`B-0034`, `B-0056`, `B-0068`, `B-0079`, `B-0083` |
| aegis-identity | ✅ | OPAQUE (`derive_login_id`, `OpaqueAccountEnvelope`, `OpaqueClientSession` с кросс-сессионным OPRF-верификатором и `Drop`), строгие пароли D-0006 с фильтрацией невидимых Unicode Format/Bidi символов (`\u{200B}`, `\u{202E}`), 24 слова (`RecoveryPhrase` с полным перемешиванием `entropy[23]` и очисткой `0..capacity()`), мультиаккаунт 3+`SupporterPass` D-0010, `PinGuard` + Duress (редактирование `Debug`), `AppDisguiseConfig`, `ChatPinLock`; исправлены `B-0007`..`B-0010`, `B-0021`, `B-0035`..`B-0038`, `B-0057`, `B-0069`, `B-0079`, `B-0084` |
| aegis-storage | ✅ | `EncryptedVaultDb` (`Drop` с автоматическим `crypto_wipe`, полное редактирование `Debug`, затирание `plaintext_body` при `purge_expired_messages`, защита от перезаписи `chat_id` по дубликату `message_id`, монотонная эпоха нонсов после `import_encrypted_backup` без копий в куче); исправлены `B-0012`, `B-0022`, `B-0039`, `B-0040`, `B-0058`, `B-0070`, `B-0079`, `B-0085` |
| aegis-protocol | ✅ | Чистая чат-крепость без звонков (`D-0021`), межграничные капсулы `seal_cross_border_capsule` / `open_cross_border_capsule` с **Pad-Before-Encrypt внутри AEAD** и 4096-раундовым растяжением ключа (`D-0023`, `normalize_channel_code`), 1:1 `SealedSenderEnvelope`, `GroupChatSession`, `LeakGuard` (Luhn + CVV/MM/YY + телефоны + email + `CryptoSeedOrPrivateKey` + PEM + Unicode ники), `strip_media_metadata`; исправлены `B-0001`..`B-0006`, `B-0023`, `B-0024`, `B-0041`..`B-0043`, `B-0059`, `B-0071`, `B-0080`, `B-0086` |
| aegis-transport | ✅ | Глобальный транспорт TCP, RFC 1928 SOCKS5h (`send_capsule_via_socks5`, `poll_capsules_via_socks5`) и слепой межграничный релей (`send_capsule_via_blind_relay`, `poll_capsules_via_blind_relay`, `D-0023`), лимит чтения `64 КБ` против OOM DoS, запрет утечки `.onion` в системный DNS, `Network Anonymity Shield`, `CoverTrafficScheduler`; исправлены `B-0013`, `B-0044`, `B-0045`, `B-0060`, `B-0072`, `B-0081`, `B-0087` |
| aegis-server | ✅ | Zero-knowledge сервер федерации (`FederationServerState`, слепые межграничные эндпоинты `/api/v1/queue/relay` и `/api/v1/queue/relay_poll` `D-0023`, HKDF-синтез 1024 B OPAQUE-записей, 0 IP-логов), демон `aegis-serverd` (буфер `64 КБ` с дочитыванием `Content-Length` по TCP-сегментам, поддержка `AEGIS_BLINDING_SALT_HEX` и энтропии запуска); исправлены `B-0015`, `B-0025`, `B-0048`, `B-0049`, `B-0064`, `B-0074`, `B-0081`, `B-0088` |
| aegis-directory | ✅ | Встроенный каталог серверов `BuiltInDirectory` со стартовыми статическими IPv4 узлами без обязательного Tor (`185.220.101.42:8443 ✓✓`, `91.108.56.110:8443 ✓✓`, `193.163.125.18:8443 ✓`) и валидным 56-символьным RFC 4648 Base32 Tor v3 `.onion` адресом; исправлены `B-0016`, `B-0026`, `B-0062`, `B-0075`, `B-0081`, `B-0089` |
| aegis-launcher | ✅ | Мастер запуска своего сервера в 1 клик (`generate_static_ip_vps_script`, `generate_docker_compose` с закреплённым `@sha256:...` дайджестом, `AEGIS_BLINDING_SALT_HEX` и `logging: driver: "none"`, `generate_cloud_init_script`, `generate_torrc_hidden_service`); исправлены `B-0017`, `B-0027`, `B-0063`, `B-0075`, `B-0081`, `B-0089` |
| aegis-plugins | ✅ | Магазин тем (`BuiltInThemes`, `ThemePack`) и песочница ботов/мостов (`BotBridgeDescriptor` с проверкой 56-символьных v3 `.onion` и защитой от SSRF); исправлены `B-0018`, `B-0028`, `B-0065`, `B-0076`, `B-0081`, `B-0089` |
| aegis-ffi | ✅ | Единый фасад `AegisClientCore` (с очисткой всей ёмкости `0..capacity()` в `zeroize_string`, реэкспортом `send_capsule_via_blind_relay`, `poll_capsules_via_blind_relay`, `send_capsule_via_socks5`, `poll_capsules_via_socks5`) + `tests/red_team_anonymity_audit.rs`; исправлены `B-0019`, `B-0029`, `B-0076`, `B-0082`, `B-0089` |
| aegis-ui-android | ✅ | Android-клиент «Aegis Quantum Aurora Vault» и релизный APK (`builds/android-apk/aegis-messenger-release.apk`, 100% Clean-Room дизайн без упоминаний сторонних брендов, капсулы Pad-Before-Encrypt + PBKDF-4096, поддержка Blind Relay, защита от повторов `seenCapsuleHexPrefixes`, затирание ключей в памяти JVM); исправлены `B-0031`, `B-0052`..`B-0055`, `B-0067`, `B-0078`, `B-0082`, `B-0090`, `B-0092` |
| aegis-ui-desktop | ✅ | Desktop-клиент «Aegis Quantum Aurora Vault» (`builds/desktop/aegis-desktop.exe`, монотонные уникальные нонсы `outbound_capsule_seq`, фильтрация повторов и своих капсул `seen_capsule_digests`, настройка Blind Relay в 1 клик, изоляция локальных заметок «Избранное», строгая проверка `Origin`); исправлены `B-0030`, `B-0050`, `B-0051`, `B-0066`, `B-0077`, `B-0082`, `B-0090`, `B-0091` |

## Сделано
- Утверждены архитектурные решения `D-0001`..`D-0023` в `docs/DECISIONS.md`
- ✅ Выполнены задачи **T-0001..T-0015** (Фазы 0–11)
- ✅ Выполнена задача **T-0016** (Фаза 12 — Слепая межграничная маршрутизация `Zero-Metadata Blind Relay`, капсулы `Pad-Before-Encrypt` + `PBKDF-4096`, закрытие `B-0083`..`B-0092` и 100% юридически чистый дизайн «Aegis Quantum Aurora Vault»):
  - Закрыты все **92 находки аудита (`B-0001`..`B-0092` в `docs/BUGS.md`)**, все **98 автотестов** проходят без единой ошибки (`0 failed`).
  - Обновлены глобальные релизные сборки в `builds/` и манифест `builds/SHA256SUMS.txt`.
- ✅ Принят **D-0024** (security reset) и **D-0025** (уточнения: libsignal XEd25519, opt-in OPAQUE, внутренний red team, P2P после MVP, группы ≤ 20, только явный экспорт).
- ✅ **Ревизия 2** документов `docs/security-reset/` утверждена владельцем
  2026-10-30 (`D-0026`).
- ✅ Создана ветка `security/t0017-plan` (только документы).
- ✅ Подготовлены ADR `docs/adr/ADR-0001..ADR-0010` на зависимости:
  libsignal, OpenMLS, rustls, arti-client, opaque-ke, argon2,
  SQLCipher/rusqlite, OHTTP, VOPRF, ed25519-dalek.

## В работе
- **T-0017 (Phase 0, планирование)**: ADR, лицензии, пиннинг libsignal,
  ответы Q-23..Q-28, гранты. Код не меняется до отдельной задачи Phase 1.

## Блокеры
- Внешний аудит — до 1.0, после финансирования; public alpha — после
  внутреннего red team.
- Default MSVC build: отсутствует `link.exe`; GNU toolchain работает.
- Открытые вопросы Q-23..Q-28 (грант, независимый сборщик, юрисдикция,
  mixnet, key transparency, Android push).
- libsignal vendored vs git dependency; провайдер rustls; параметры
  Argon2id; вариант SQLCipher; ciphersuite VOPRF — закрываются в Phase 1/2
  spike (см. `docs/adr/README.md`).
