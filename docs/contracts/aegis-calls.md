# Контракт: aegis-calls
Версия контракта: 0.1

## Ответственность
Реализует голосовые и видеозвонки со сквозным шифрованием медиапотоков и обязательной защитой сетевых метаданных (PLAN.md §8.2, D-0008):
- Управление конфигурацией вызовов (`CallConfig`), в которой по умолчанию принудительно включён режим **`relay_only = true` (TURN Relay-Only)**, чтобы собеседник никогда не узнал P2P IP-адрес участника;
- Двойное шифрование медиа-фреймов: транспортное `SRTP` + сквозное кадровое шифрование `SFrame` (`require_e2ee_media = true`) на ключах, согласованных через `aegis-protocol`;
- Адаптивное управление битрейтом (Opus для голоса, VP9/AV1/H.264 для видео) с целевой односторонней задержкой `< 150 мс` (PLAN.md §8.2);
- Передача сигнализации (offer/answer/ICE-кандидаты релея) исключительно внутри защищённых E2EE-очередей `aegis-protocol` под `Sealed Sender`.

## Публичное API (функции, типы, ошибки)

### Типы
- `CallConfig { relay_only: bool, require_e2ee_media: bool, target_max_latency_ms: u16, max_bitrate_kbps: u32 }`
  - `CallConfig::default()` -> `relay_only: true`, `require_e2ee_media: true`, `target_max_latency_ms: 150`, `max_bitrate_kbps: 1500`.
- `CallSessionId([u8; 16])` — эфемерный идентификатор сессии звонка.
- `TurnRelayAllocation { relay_endpoint: String, ephemeral_username: String, ephemeral_token: ZeroizingBuffer, expires_at_unix: u64 }`
- `MediaFrameRatchetKey` — ключ сквозного шифрования медиа-кадров `SFrame` (`ZeroizingBuffer`).

### Основные функции
- `CallConfig::is_privacy_preserving(&self) -> bool`
- `validate_call_config(config: &CallConfig) -> Result<(), CallError>`
- `start_outgoing_call(config: &CallConfig, relay: &TurnRelayAllocation, media_key: MediaFrameRatchetKey) -> Result<CallSessionId, CallError>`
- `encrypt_media_frame(session: &CallSessionId, frame_counter: u64, raw_opus_or_video: &[u8]) -> Result<Vec<u8>, CallError>`
- `decrypt_media_frame(session: &CallSessionId, encrypted_frame: &[u8]) -> Result<Vec<u8>, CallError>`

### Ошибки (`CallError`)
- `UnencryptedMediaForbidden` — попытка инициировать звонок с `require_e2ee_media == false` (**Fail Closed**).
- `DirectPeerCandidateRejected` — попытка передать или принять прямой ICE-кандидат (`host`, `srflx`, `prflx`) при включённом `relay_only = true`.
- `TurnAllocationExpired` — истёк срок жизни анонимных учётных данных TURN-релея.
- `FrameAuthenticationFailed` — ошибка проверки AEAD-тега `SFrame` на входящем медиа-кадре.

## Гарантии
1. **Защита IP в звонках по умолчанию (D-0008):** `CallConfig::default()` всегда выставляет `relay_only = true`. Локальные интерфейсы и STUN-кандидаты (`host`, `srflx`) не собираются и не отправляются собеседнику.
2. **Обязательное сквозное шифрование медиа:** TURN-сервер видит только зашифрованные пакеты и не имеет ключей `SFrame`.
3. **Fail Closed:** любой повреждённый или неподписанный медиа-кадр немедленно отбрасывается без передачи в аудио/видео декодер.

## Запрещено вызывающему
- Запрещено отключать `require_e2ee_media` (незашифрованные звонки не поддерживаются на уровне ядра).
- Запрещено переключать `relay_only` в `false` без явного предупреждения пользователя в UI о раскрытии IP-адреса собеседнику.

## Зависимости
- Внутренние модули: `aegis-protocol`, `aegis-transport`.

## История изменений
- `0.1` (2026-10-20, T-0002 / T-0003): Первичная спецификация контракта.
