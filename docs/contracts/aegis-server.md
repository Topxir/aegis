# Контракт: aegis-server
Версия контракта: 0.1

## Ответственность
Реализует легковесный сервер федерации с нулевым знанием (**Untrusted Postman**, PLAN.md §6.1, D-0002, D-0007):
- Хранение обезличенных записей `OPAQUE` (`login_id = KDF(ник, соль)`) и зашифрованных конвертов `AccountVault` без знания ников и паролей;
- Обслуживание анонимных односторонних очередей (`Unidirectional Queues`) с фиксированным паддингом пакетов (`256B`..`16KB`) и автоматическим удалением по `TTL` или после подтверждённой доставки;
- Защита от перечисления аккаунтов (одинаковый размер и время ответа при запросе существующего и несуществующего `login_id`);
- Защита от DDoS, спама и брутфорса (**Anti-DDoS Shield**, D-0007): выдача и верификация stateless-пазлов `BLAKE3 Proof-of-Work` с адаптивной сложностью, in-memory rate-limiting без записи IP-адресов на диск;
- Встроенный TURN-релей для звонков в режиме `Relay-Only` по краткоживущим анонимным токенам;
- Эхо-ответ для клиентского `Network Anonymity Shield` (возврат обезличенного индикатора видимой подсети внутри зашифрованной сессии без логирования).

## Публичное API (RPC / Wire Endpoints, типы, ошибки)

### Сетевые эндпоинты (поверх QUIC / TLS 1.3)
- `GetServerInfo` -> `ServerPublicInfo { protocol_version: u16, server_salt: [u8; 32], server_pubkey: Ed25519PublicKey, current_pow_difficulty: u8, directory_cert: Option<ServerCert> }`
- `RequestPowChallenge(ContextTag)` -> `PowChallenge`
- `OpaqueRegister { pow: PowSolution, login_id: [u8; 32], opaque_req: Vec<u8> }` -> `OpaqueRegResponse`
- `OpaqueLoginStep1 { pow: PowSolution, login_id: [u8; 32], credential_req: Vec<u8> }` -> `OpaqueLoginResponse`
- `UpdateAccountVault { session_mac: [u8; 32], encrypted_vault: Vec<u8> }` -> `VaultAck`
- `CreateAnonymousQueue { pow: PowSolution, queue_id: [u8; 32], read_auth_pubkey: Ed25519PublicKey, write_cap_hash: [u8; 32], ttl_sec: u32 }` -> `QueueCreatedAck`
- `PostSealedMessage { queue_id: [u8; 32], write_cap_token: [u8; 32], pow: Option<PowSolution>, envelope: SealedEnvelope }` -> `DeliveryAck`
- `ReadQueueMessages { queue_id: [u8; 32], timestamp: u64, read_signature: Ed25519Signature }` -> `Vec<SealedEnvelope>`
- `DeleteQueue { queue_id: [u8; 32], timestamp: u64, read_signature: Ed25519Signature }` -> `QueueDeletedAck`
- `AllocateTurnRelayCredentials { pow: PowSolution }` -> `EphemeralTurnCredentials`
- `NetworkEchoCheck` -> `NetworkEchoResponse { subnet_hash: [u8; 16], is_tor_exit: bool }`

### Ошибки сервера (`ServerWireError`)
- `PowRequired(PowChallenge)` — требуется решить пазл `BLAKE3 PoW` указанной сложности.
- `RateLimitExceeded { retry_after_ms: u32 }` — превышен лимит запросов в скользящем окне ОЗУ.
- `InvalidWriteCapability` — неверный `write_cap_token` для целевой односторонней очереди.
- `InvalidReadSignature` — неверная подпись `Ed25519` владельца очереди.
- `InvalidEnvelopePadding` — размер пакета не равен `256`, `1024`, `4096` или `16384` байт.
- `QueueQuotaFull` — очередь переполнена (защита диска сервера от переполнения).

## Гарантии
1. **Strict No-IP-Logs Policy (AGENTS.md §2 п.3):** сервер физически не имеет кода записи IP-адресов в базу данных или файлы логов. Rate-limiting работает исключительно в оперативной памяти по `BLAKE3(ephemeral_ram_salt || ip_bytes)`, где `ephemeral_ram_salt` пересоздаётся в RAM каждые 10 минут.
2. **Константный профиль ответа OPAQUE:** при `OpaqueLoginStep1` для несуществующего `login_id` сервер генерирует детерминированный маскирующий `CredentialResponse` через `HKDF(server_oprf_seed, login_id)`, поэтому атакующий не может узнать, зарегистрирован ли данный `login_id`.
3. **Разрыв связи между аккаунтом и очередями:** в схеме БД сервера отсутствуют поля или таблицы, связывающие `login_id` с `queue_id`.
4. **Немедленное удаление доставленных сообщений:** после подтверждения получения пакета клиентом (`ACK`) или истечения `TTL` запись в таблице `messages` немедленно удаляется.

## Запрещено вызывающему / оператору
- Сервер отвергает любые пакеты `PostSealedMessage`, размер которых не соответствует фиксированным корзинам паддинга (`InvalidEnvelopePadding`).
- Конфигурация сервера не позволяет включить логирование IP-адресов или содержимого пакетов на уровне релизной сборки.

## Зависимости
- Внутренние модули: `aegis-crypto`, `aegis-protocol`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
