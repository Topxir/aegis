# Состояние проекта

Обновляется после каждой задачи. Легенда: ✅ готово · 🔧 в работе · ❌ не начато · ⚠ проблема

Текущая фаза: **7. Экосистема, десктоп и Android клиенты (Фазы 0–7 завершены ✅ — готовы к Фазе 8: харденинг и релиз)**
Обновлено: 2026-10-20

| Модуль | Статус | Заметки |
|---|---|---|
| aegis-crypto | ✅ | SHA-256, HMAC-SHA256, HKDF-SHA256, ChaCha20-Poly1305 AEAD (RFC 8439), гибридный PQXDH, `RatchetSession` (`MAX_SKIPPED_KEYS = 64`), `solve_pow`; исправлены `B-0011`, `B-0020`, `B-0032`..`B-0034` |
| aegis-identity | ✅ | OPAQUE (`derive_login_id`, `OpaqueAccountEnvelope`, `OpaqueClientSession`), строгие пароли D-0006, 24 слова (`RecoveryPhrase`), мультиаккаунт 3+`SupporterPass` D-0010, `PinGuard` + Duress, `AppDisguiseConfig`, `ChatPinLock`; исправлены `B-0007`..`B-0010`, `B-0021`, `B-0035`..`B-0038` |
| aegis-storage | ✅ | `EncryptedVaultDb` (AEAD KV, контакты, исчезающие сообщения, `get_messages_for_chat`, локальный поиск, заметки «Избранное», экспорт/импорт `AEGISBAK`, `crypto_wipe`); исправлены `B-0012`, `B-0022`, `B-0039`, `B-0040` |
| aegis-protocol | ✅ | Паддинг `PADDING_BUCKETS`, `LeakGuard` (Luhn + CVV/MM/YY + телефоны + email + свой ник), очистка EXIF/GPS (`strip_media_metadata`), `ViewOncePayload`, `ContactInvite`, 60-значный Safety Number, `GroupChatSession` (MLS эпохи); исправлены `B-0001`..`B-0006`, `B-0023`, `B-0024`, `B-0041`..`B-0043` |
| aegis-transport | ✅ | `Network Anonymity Shield`, Kill Switch D-0008, `CoverTrafficScheduler` (256 B dummy-пакеты), профили Tor/SOCKS5/ObfuscatedBridge (`ProxyConfig`), живая миграция сервера (`ServerMigrationNotice`); исправлены `B-0013`, `B-0044`, `B-0045` |
| aegis-calls | ✅ | `CallConfig` (принудительный `relay_only` TURN + SFrame E2EE), анонимайзер голоса `anonymize_audio_pcm16` (`VoicePitchMode`), адаптивный битрейт `adapt_call_bitrate`, `filter_ice_candidate`; исправлены `B-0014`, `B-0046`, `B-0047` |
| aegis-server | ✅ | Zero-knowledge сервер федерации (`FederationServerState`, constant-shape OPAQUE 1024 B, 1-клик удаление спам-очередей, глобальные квоты памяти), бинарный демон `aegis-serverd` и веб-портал поддержки/донатов (`SupportPortalState`); исправлены `B-0015`, `B-0025`, `B-0048`, `B-0049` |
| aegis-directory | ✅ | Встроенный каталог серверов `BuiltInDirectory` (`✓✓` Official, `✓` Verified, `.onion`), `SupportCertificate`, пороговая схема `M-of-N` и списки отзыва; исправлены `B-0016`, `B-0026` |
| aegis-launcher | ✅ | Мастер запуска своего сервера в 1 клик (`generate_docker_compose`, `generate_cloud_init_script`, `generate_torrc_hidden_service`, `format_server_invite_uri`); исправлены `B-0017`, `B-0027` |
| aegis-plugins | ✅ | Магазин тем (`BuiltInThemes`, `ThemePack`, включая `CalculatorStealth`), песочница ботов и мостов Matrix/XMPP (`BotBridgeDescriptor`), защита от эксфильтрации; исправлены `B-0018`, `B-0028` |
| aegis-ffi | ✅ | Единый фасад `AegisClientCore` + C-ABI/JNI точки входа для Android и Desktop UI (`RU`/`EN`); исправлены `B-0019`, `B-0029` |
| aegis-ui-android | ✅ | Android-клиент (Jetpack Compose, `FLAG_SECURE`, инкогнито-клавиатура, `CalculatorDisguiseAlias`, Zero-GMS `AegisBackgroundService`, Android StrongBox Keystore); исправлены `B-0031`, `B-0052`..`B-0055` |
| aegis-ui-desktop | ✅ | Кроссплатформенный Desktop-клиент (`aegis-desktop --self-test` и интерактивный локальный GUI `aegis-desktop --gui --port 7878`); исправлены `B-0030`, `B-0050`, `B-0051` |

## Сделано
- План и AGENTS.md созданы
- Утверждены архитектурные решения `D-0001`..`D-0018` в `docs/DECISIONS.md` и закрыты вопросы владельцу (`Q-1`..`Q-7`, `Q-9` в `docs/QUESTIONS.md`)
- ✅ Выполнена задача **T-0001**: модель угроз и политика безопасности (`docs/spec/threat-model.md`, отчёт `docs/reports/2026-10-20_T-0001.md`)
- ✅ Выполнена задача **T-0002**: выбор протокола, сетевой модели, криптонабора (`docs/spec/protocol-selection.md`) и контракты всех 11 модулей ядра v0.1 в `docs/contracts/*.md` (отчёт `docs/reports/2026-10-20_T-0002.md`)
- ✅ Выполнена задача **T-0003**: каркас Rust workspace, строгие линтеры (`forbid(unsafe_code)`, запрет `unwrap`/`expect`/`panic`), CI (`.github/workflows/ci.yml`), `deny.toml`, `rust-toolchain.toml` и сканер секретов (отчёт `docs/reports/2026-10-20_T-0003.md`)
- ✅ Выполнены задачи **T-0004..T-0010** (Фазы 1–7): криптоядро, OPAQUE, зашифрованное хранилище `EncryptedVaultDb`, протокол 1:1 и групповые чаты MLS, очистка EXIF/GPS, View-Once, демон сервера `aegis-serverd` с веб-порталом поддержки и слепыми токенами `SupporterPass`, анонимайзер голоса, мастер запуска сервера в 1 клик, магазин тем, Desktop-приложение (`aegis-ui-desktop`) и Android-приложение (`apps/aegis-android`) (отчёт `docs/reports/2026-10-20_T-0004_T-0010.md`)
- ✅ Проведён полный многоступенчатый Red-Team аудит Фаз 0–7: выявлены, задокументированы в `docs/BUGS.md` (`B-0001`..`B-0055`), исправлены и покрыты регрессионными юнит-тестами все 55 находок (86 тестов в workspace, 0 предупреждений Clippy).

## В работе
- Нет активных задач (Фазы 0–7 полностью завершены и проверены; ожидание команды владельца)

## Блокеры
- Нет активных блокеров
