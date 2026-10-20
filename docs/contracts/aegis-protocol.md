# Контракт: aegis-protocol
Версия контракта: 0.1

## Ответственность
Реализует криптографический и пакетный протокол мессенджера (PLAN.md §5, §7, D-0002, D-0006, D-0009):
- Формирование и разбор одноразовых и многоразовых приглашений (`InviteLink` / QR) с гибридными ключами `Aegis-PQXDH` (`X25519 + ML-KEM-768`) и адресами анонимных односторонних очередей;
- Установка и продвижение сессий `Double Ratchet` (1:1 чаты, с Фазы 1) и `MLS` (группы, Фаза 6);
- Упаковка и распаковка конвертов **`Sealed Sender`** (скрытие отправителя от сервера) и выравнивание пакетов фиксированным паддингом (`256 B`, `1 KB`, `4 KB`, `16 KB`);
- Локальный офлайн DLP-анализатор чувствительных данных перед отправкой — **`LeakGuard`** (детекция банковских карт по алгоритму Луна + CVV/срока действия, телефонов, email, сид-фраз BIP-39 и собственного логина **без ложных срабатываний**);
- Формирование зашифрованных анонимных тикетов в официальную поддержку (`SupportTicketPayload`), совместимых с клиентским чатом поддержки и веб-порталом.

## Публичное API (функции, типы, ошибки)

### Типы
- `ProtocolVersion(u16)` — текущая версия протокола (`v1 = 1`).
- `PaddingBucket` — корзины фиксированного размера пакета: `B256 = 256`, `B1024 = 1024`, `B4096 = 4096`, `B16384 = 16384`.
- `QueueAddress { server_endpoint: String, queue_id: [u8; 32], write_cap_token: [u8; 32] }`
- `ContactInvite { version: ProtocolVersion, inviter_queue: QueueAddress, prekey_bundle: HybridPreKeyBundle, expires_at: u64, max_uses: u16 }`
- `SealedEnvelope { bucket: PaddingBucket, ciphertext: Vec<u8> }`
- `LeakScanResult`:
  - `Clean`
  - `WarningsFound(Vec<LeakFinding>)`
- `LeakFinding { kind: LeakKind, span_range: Range<usize>, masked_preview: String, severity: LeakSeverity }`
- `LeakKind` — `PaymentCardWithLuhn`, `PaymentCardWithCvvAndExpiry`, `PhoneNumber`, `EmailAddress`, `CryptoSeedOrPrivateKey`, `OwnLoginNickname`.
- `SupportTicketPayload { category: TicketCategory, subject: String, body: String, reply_queue: QueueAddress, attachment_keys: Vec<AttachmentRef> }`

### Основные функции
- `scan_outgoing_message_leaks(text: &str, own_nickname: &str) -> LeakScanResult`
- `mask_detected_leaks(text: &str, findings: &[LeakFinding]) -> String`
- `create_contact_invite(storage: &EncryptedStorage, server_endpoint: &str, ttl_sec: u64, max_uses: u16) -> Result<(ContactInvite, StoredQueueBinding), ProtocolError>`
- `accept_contact_invite(storage: &EncryptedStorage, invite: &ContactInvite) -> Result<(ContactId, OutgoingQueuePacket), ProtocolError>`
- `seal_and_pad_message(storage: &EncryptedStorage, recipient: &ContactId, content: &PlaintextContent, leak_override_confirmed: bool) -> Result<SealedEnvelope, ProtocolError>`
- `unseal_and_decrypt_message(storage: &EncryptedStorage, queue_id: &[u8; 32], envelope: &SealedEnvelope) -> Result<DecryptedMessageEvent, ProtocolError>`
- `create_encrypted_support_ticket(ticket: &SupportTicketPayload, support_cert: &VerifiedSupportCert) -> Result<SealedEnvelope, ProtocolError>`

### Ошибки (`ProtocolError`)
- `LeakGuardBlocked(Vec<LeakFinding>)` — в тексте обнаружены чувствительные данные (например, банковская карта, прошедшая проверку Луна + CVV), а флаг `leak_override_confirmed` равен `false`.
- `UnsupportedProtocolVersion(u16)` — неизвестная версия пакета.
- `InvalidPaddingOrEnvelopeSize` — размер пакета не кратен разрешённым корзинам `PaddingBucket` (`256B`..`16KB`).
- `SealedSenderVerificationFailed` — внутренняя подпись отправителя или ключ сессии невалидны (**Fail Closed**).
- `DuplicateOrReplayedMessage` — повтор пакета (отклонено по счётчику цепочки Double Ratchet).
- `InviteExpiredOrInvalid` — истёк срок действия приглашения или нарушена подпись пре-ключей.

## Гарантии
1. **Обязательный проход через `LeakGuard` (D-0009):** функция `seal_and_pad_message` автоматически запускает `scan_outgoing_message_leaks` перед шифрованием. Без явного подтверждения пользователя (`leak_override_confirmed = true`) сообщение с номером карты (валидным по Луну), CVV, телефоном, почтой или сид-фразой **не может быть зашифровано и отправлено**.
2. **Точность `LeakGuard` (Zero False Positives):** детектор банковских карт срабатывает только при прохождении математической проверки алгоритма Луна (Luhn) и префикса BIN, исключая ложные тревоги на обычных числах в переписке.
3. **Неразличимость пакетов (`Sealed Sender` + Паддинг):** все исходящие конверты `SealedEnvelope` имеют размер строго `256`, `1024`, `4096` или `16384` байта и не содержат в открытых заголовках ни `login_id`, ни публичного ключа отправителя.
4. **Безопасность парсеров внешних данных:** десериализация входящих пакетов не использует `unwrap`/`expect`, ограничивает глубину и размер аллокаций и покрывается фаззингом (`cargo-fuzz`).

## Запрещено вызывающему
- Запрещено передавать `leak_override_confirmed = true` по умолчанию без показа пользователю предупреждения в UI.
- Запрещено отправлять сообщения в сеть в обход `seal_and_pad_message`.

## Зависимости
- Внутренние модули: `aegis-crypto`, `aegis-identity`, `aegis-storage`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
