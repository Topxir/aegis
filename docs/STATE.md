# Состояние проекта

Обновляется после каждой задачи. Легенда: ✅ готово · 🔧 в работе · ❌ не начато · ⚠ проблема

Текущая фаза: **0. Фундамент (завершена ✅ — готова к переходу в Фазу 1)**
Обновлено: 2026-10-20

| Модуль | Статус | Заметки |
|---|---|---|
| aegis-crypto | 🔧 | Контракт v0.1 (`docs/contracts/aegis-crypto.md`) + базовый крейт Фазы 0 (`ZeroizingBuffer`, `constant_time_eq`, `PowVerifier`) |
| aegis-identity | 🔧 | Контракт v0.1 (`docs/contracts/aegis-identity.md`) + базовый крейт Фазы 0 (политика паролей D-0006, генератор ников, мультиаккаунты 3+`SupporterPass` D-0010, `PinGuard` + Duress) |
| aegis-storage | 🔧 | Контракт v0.1 (`docs/contracts/aegis-storage.md`) + базовый крейт Фазы 0 (`SCHEMA_VERSION`, `EncryptedStoreHeader`, `crypto_wipe`) |
| aegis-protocol | 🔧 | Контракт v0.1 (`docs/contracts/aegis-protocol.md`) + базовый крейт Фазы 0 (`PADDING_BUCKETS`, DLP-сканер `LeakGuard` с алгоритмом Луна D-0009, `SupportTicket`) |
| aegis-transport | 🔧 | Контракт v0.1 (`docs/contracts/aegis-transport.md`) + базовый крейт Фазы 0 (`Network Anonymity Shield`, детектор утечки VPN/Tor, Kill Switch D-0008) |
| aegis-calls | 🔧 | Контракт v0.1 (`docs/contracts/aegis-calls.md`) + базовый крейт Фазы 0 (`CallConfig`: `relay_only = true`, `require_e2ee_media = true`) |
| aegis-server | 🔧 | Контракт v0.1 (`docs/contracts/aegis-server.md`) + базовый крейт Фазы 0 (`compute_pow_difficulty` Anti-DDoS D-0007, `QueueQuota`) |
| aegis-directory | 🔧 | Контракт v0.1 (`docs/contracts/aegis-directory.md`) + базовый крейт Фазы 0 (пороговая проверка `M-of-N` `ThresholdPolicy`, списки отзыва D-0011) |
| aegis-launcher | 🔧 | Контракт v0.1 (`docs/contracts/aegis-launcher.md`) + базовый крейт Фазы 0 (`LaunchTarget`, `build_launch_plan`) |
| aegis-plugins | 🔧 | Контракт v0.1 (`docs/contracts/aegis-plugins.md`) + базовый крейт Фазы 0 (`PluginManifest`, запрет доступа к ключам) |
| aegis-ffi | 🔧 | Контракт v0.1 (`docs/contracts/aegis-ffi.md`) + единый пограничный крейт для UI (`Locale::Ru`/`En`, `core_version_info`) |
| aegis-ui-android | ❌ | Запланировано на Фазу 3 (через `aegis-ffi`) |
| aegis-ui-desktop | ❌ | Запланировано на Фазу 6 (через `aegis-ffi`) |

## Сделано
- План и AGENTS.md созданы
- Утверждены архитектурные решения Фазы 0 (`D-0001`..`D-0012` в `docs/DECISIONS.md`) и закрыты вопросы владельцу (`Q-1`..`Q-7`, `Q-9` в `docs/QUESTIONS.md`)
- ✅ Выполнена задача **T-0001**: модель угроз и политика безопасности (`docs/spec/threat-model.md`, отчёт `docs/reports/2026-10-20_T-0001.md`)
- ✅ Выполнена задача **T-0002**: выбор протокола, сетевой модели, криптонабора (`docs/spec/protocol-selection.md`) и контракты всех 11 модулей ядра v0.1 в `docs/contracts/*.md` (отчёт `docs/reports/2026-10-20_T-0002.md`)
- ✅ Выполнена задача **T-0003**: каркас Rust workspace (11 крейтов), строгие линтеры (`forbid(unsafe_code)`, запрет `unwrap`/`expect`/`panic`), CI (`.github/workflows/ci.yml`), `deny.toml`, `rust-toolchain.toml` и сканер секретов (отчёт `docs/reports/2026-10-20_T-0003.md`)

## В работе
- Нет активных задач (Фаза 0 полностью завершена; ожидание команды владельца на старт Фазы 1)

## Блокеры
- Нет активных блокеров Фазы 0 (решения D-0001..D-0012 приняты)
