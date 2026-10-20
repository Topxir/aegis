# Контракт: aegis-ffi
Версия контракта: 0.1

## Ответственность
Единый публичный пограничный слой (`FFI / UniFFI`) между доверенным Rust-ядром и платформенными интерфейсами `aegis-ui-android`, `aegis-ui-desktop`, `aegis-ui-ios` (`AGENTS.md §2 п.6`, `§3`, `§4`, `D-0001`, `D-0005`, `D-0012`):
- Предоставляет безопасное, свободное от сырых указателей и ключей API для всех UI-платформ;
- Инкапсулирует внутренние состояния криптографии, рэтчетов и БД внутри Rust-ядра, передавая в UI только готовые к отображению DTO, статусы безопасности и локализованные коды ошибок;
- Обеспечивает поддержку локализации `RU` + `EN` со старта (`Locale::Ru`, `Locale::En`, D-0012) и контроль версий протокола/схемы (`CoreVersionInfo`).

## Публичное API (функции, типы, ошибки)

### Экспортируемые типы и реэкспорты для UI
- `Locale` — `Ru`, `En` (D-0012).
- `CoreVersionInfo { crypto_suite_version: u16, protocol_version: u16, storage_schema_version: u32 }`
- Из `aegis-identity`: `generate_nickname`, `validate_nickname`, `validate_password`, `NicknameError`, `PasswordPolicyError`.
- Из `aegis-protocol`: `scan_message_for_leaks`, `redact_leaks`, `LeakKind`, `LeakWarning`.
- Из `aegis-transport`: `evaluate_network_shield`, `NetworkRouteStatus`, `RouteProbe`, `ShieldEvaluation`.

### Основные функции
- `core_version_info() -> CoreVersionInfo`
- Все пользовательские действия (онбординг, проверка пароля/PIN, проверка `LeakGuard` перед отправкой, отображение индикатора `Network Anonymity Shield`, мастер запуска сервера `aegis-launcher`) вызываются UI исключительно через функции `aegis-ffi`.

## Гарантии
1. **Разделение слоёв (AGENTS.md §2 п.6):** UI не знает про криптографию и никогда не получает `ZeroizingBuffer`, `DB_KEY`, `export_key` или внутренние ключи `Double Ratchet`.
2. **Отсутствие паник на границе FFI:** все функции возвращают типизированные структуры или `Result<T, Error>` без `unwrap`/`panic`.
3. **Единообразие поведения на всех платформах:** валидация пароля (D-0006), DLP-сканер `LeakGuard` (D-0009), квоты мультиаккаунтов (D-0010) и `Network Anonymity Shield` (D-0008) работают идентично на Android, Desktop и iOS.

## Запрещено вызывающему (UI-слою)
- Запрещено импортировать внутренние крейты ядра напрямую в обход `aegis-ffi` (`AGENTS.md §4`).
- Запрещено логировать в системный лог ОС (`Logcat`, `NSLog`, `stdout`) текст сообщений, пароли или PIN, передаваемые через FFI.
- Запрещено делать скриншоты или сохранять в системный буфер обмена чувствительные данные без явного действия пользователя.

## Зависимости
- Внутренние модули: `aegis-crypto`, `aegis-identity`, `aegis-storage`, `aegis-protocol`, `aegis-transport`, `aegis-calls`, `aegis-server`, `aegis-directory`, `aegis-launcher`, `aegis-plugins`.

## История изменений
- `0.1` (2026-10-20, T-0002 / T-0003): Первичная спецификация контракта.
