# Контракт: aegis-launcher
Версия контракта: 0.1

## Ответственность
Реализует встроенный в клиент мастер запуска собственного сервера федерации в 1 клик (PLAN.md §6.2, AGENTS.md §1, §3):
- Генерация воспроизводимых конфигураций развёртывания `aegis-server` для выбранного целевого окружения (`LaunchTarget`):
  - `VpsDocker` — готовый `docker-compose.yml` / `cloud-init` манифест с закреплённым SHA-256 хэшем образа, генерацией ключей сервера и автоматическим выпуском ссылки-приглашения;
  - `DesktopLocal` — запуск локального демона `aegis-server` на десктопе;
  - `TorOnionService` — конфигурация сервера как скрытого сервиса Tor (`.onion`), при которой IP-адрес сервера никогда не раскрывается;
  - `AndroidTestOnly` — локальный тестовый режим на Android с обязательным предупреждением о ненадёжности телефона как постоянного сервера (`requires_ephemeral_warning = true`, PLAN.md §2, §6.2);
- Проверка соответствия параметров запускаемого сервера политике нулевого логирования (`no-ip-logs`) и дефолтному `TTL` очередей (`DEFAULT_QUEUE_TTL_SECS`).

## Публичное API (функции, типы, ошибки)

### Типы
- `LaunchTarget`:
  - `VpsDocker`
  - `DesktopLocal`
  - `TorOnionService`
  - `AndroidTestOnly`
- `LaunchPlan { target: LaunchTarget, requires_ephemeral_warning: bool, queue_ttl_secs: u64 }`
- `GeneratedServerBundle { plan: LaunchPlan, server_public_key: [u8; 32], compose_or_config_manifest: String, admin_invite_uri: String }`

### Основные функции
- `build_launch_plan(target: LaunchTarget) -> LaunchPlan`
- `generate_server_bundle(plan: &LaunchPlan, endpoint_host: &str, server_pubkey: [u8; 32]) -> Result<GeneratedServerBundle, LauncherError>`

### Ошибки (`LauncherError`)
- `InvalidEndpointHost` — некорректный адрес хоста или `.onion`-домена.
- `InsecureQueueTtl` — указан нулевой или превышающий лимит `queue_ttl_secs`.
- `UnacknowledgedEphemeralWarning` — попытка запустить `AndroidTestOnly` без подтверждения пользователем предупреждения о батарее/NAT.

## Гарантии
1. **Честное предупреждение на мобильных платформах (PLAN.md §2, §6.2):** для `LaunchTarget::AndroidTestOnly` поле `requires_ephemeral_warning` всегда равно `true`.
2. **Безопасные настройки по умолчанию:** генерируемые манифесты принудительно включают `no_ip_logs = true`, обязательный `BLAKE3 PoW` и `DEFAULT_QUEUE_TTL_SECS` из `aegis-server`.
3. **Готовность к проверке каталогом (`aegis-directory`):** манифест фиксирует воспроизводимый хэш бинарника сервера для последующего получения галочки `Verified ✓`.

## Запрещено вызывающему
- Запрещено сохранять приватный ключ запускаемого сервера в открытом виде вне зашифрованного хранилища или защищённого буфера.
- Запрещено скрывать предупреждение `requires_ephemeral_warning` при выборе `AndroidTestOnly`.

## Зависимости
- Внутренние модули: `aegis-server`, `aegis-directory`.

## История изменений
- `0.1` (2026-10-20, T-0002 / T-0003): Первичная спецификация контракта.
