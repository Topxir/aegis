# Aegis Protocol v2 — спецификация (APPROVED rev.2)

**Статус: УТВЕРЖДЕНО владельцем 2026-10-30. Версия: 0.2. Дата: 2026-10-30.**
Ревизия 2 учитывает ответы владельца: libsignal XEd25519, opt-in OPAQUE,
public alpha после внутреннего red team, P2P после MVP, группы ≤ 20,
только явный экспорт. Документ утверждён; байтовые форматы уточняются в
ADR и Phase 1 spike после выбора библиотек.

## 0. Принципы

1. **Никакой самописной криптографии.** Только audited crates и публичные
   спецификации: Signal PQXDH/Double Ratchet, MLS RFC 9420, TLS 1.3,
   OHTTP RFC 9458, OPAQUE RFC 9807, Argon2id RFC 9106, ML-KEM FIPS 203.
2. **Fail closed.** Любая ошибка подписи, MAC, сертификата, версии или
   паддинга — отказ, а не «пропустим».
3. **Минимум метаданных.** Relay не знает отправителя, контактный граф,
   IP-логи и историю. Account service не знает переписку.
4. **Ключи только на клиенте.** Сервер не хранит приватные ключи, открытый
   текст и историю сообщений. OPAQUE-сервер хранит только verifier и
   зашифрованный seed-backup.
5. **Один протокол — несколько реализаций.** Rust core, Kotlin/Swift
   обёртки; cross-implementation тесты.
6. **Крипто-агильность.** Версия протокола и ciphersuite ID; downgrade
   protection.
7. **Никаких «тихих» компромиссов.** Если библиотека не поддерживает
   свойство (например, header encryption), мы не изобретаем свой слой, а
   фиксируем ограничение в ADR и threat model.

## 1. Обозначения

| Обозначение | Значение |
|---|---|
| `AIK` | Account identity key: Curve25519, XEdDSA (подпись + DH), корень аккаунта |
| `DIK` | Device identity key: Curve25519, XEdDSA, ключ конкретного устройства для libsignal |
| `SPK` | Signed prekey (Curve25519), подписан device identity key |
| `OPK` | One-time prekey (Curve25519) |
| `PQPK` | Post-quantum prekey (ML-KEM, параметр libsignal) |
| `EK` | Ephemeral X25519 key |
| `SK` | Shared secret / root key |
| `MK` | Message key |
| `CID` | Ciphersuite ID |
| `AAD` | Additional authenticated data |
| `IKM` | Input key material |
| `read_token` | 32-байтный секрет чтения inbox |
| `inbox_id` | 16-байтный публичный адрес очереди |

**Важно:** пользовательская идентичность — это libsignal identity key
(Curve25519 + XEdDSA), а не отдельная пара Ed25519 + X25519. Отдельный
Ed25519 используется только для инфраструктурных подписей (relay
descriptors, directory, релизы), не для PQXDH.

## 2. Криптографический набор

| Задача | Выбор | Библиотека (кандидат) |
|---|---|---|
| Hash | SHA-256 / SHA-512 | `sha2` |
| MAC | HMAC-SHA-256 | `hmac` |
| KDF | HKDF-SHA-256 | `hkdf` |
| AEAD сообщений | Как в libsignal (не менять) | `libsignal-protocol` |
| AEAD файлов | XChaCha20-Poly1305 | `chacha20poly1305` |
| Подписи пользователя | XEdDSA (Curve25519) | `libsignal-protocol` |
| Подписи инфраструктуры | Ed25519 | `ed25519-dalek` |
| DH | X25519 | внутри `libsignal-protocol`; не использовать напрямую для протокола |
| KEM | ML-KEM (параметр libsignal; ADR) | `libsignal-protocol` / `ml-kem` |
| Пароль (opt-in) | OPAQUE RFC 9807 + Argon2id | `opaque-ke`, `argon2` |
| CSPRNG | OS CSPRNG | `getrandom` |
| Constant-time | `subtle` | `subtle` |
| Zeroization | `zeroize` / `secrecy` | `zeroize`, `secrecy` |
| TLS | TLS 1.3 | `rustls` |
| QUIC | QUIC v1 | `quinn` |
| Tor | Arti | `arti-client` |
| OHTTP | RFC 9458 | `ohttp` |
| Blind tokens | VOPRF RFC 9497 | `voprf` |
| Storage | SQLCipher | `rusqlite` + SQLCipher |

**Запрещено:** писать SHA-256, HMAC, HKDF, ChaCha20, Poly1305, AEAD,
X25519, ML-KEM, XEdDSA, ratchet, OPAQUE или TLS самостоятельно. Текущий
`aegis-crypto` с самописными примитивами в публичный релиз не идёт.

**Лицензия libsignal:** AGPL-3.0; проект — AGPL-3.0-or-later. Совместимо,
но libsignal нужно вендорить/пиновать по коммиту и хэшу. Это ADR, а не
решение «по умолчанию».

## 3. Идентичность

### 3.1 Seed

- 32 байта из OS CSPRNG.
- 24 слова BIP-39 для бэкапа (опционально; можно QR).
- HKDF с доменами:
  - `aegis-account-id-v2` → `account_id` (16 байт);
  - `aegis-account-ik-v2` → `AIK` (Curve25519, XEdDSA), корень аккаунта;
  - `aegis-device-ik-v2 || device_id` → `DIK` (Curve25519, XEdDSA);
  - `aegis-device-kem-v2 || device_id` → ML-KEM keypair (параметр libsignal);
  - `aegis-inbox-token-v2 || device_id` → `read_token` (32 байта).
- Seed никогда не покидает устройство; на сервер не уходит.
- `AIK` не используется для сообщений и не отправляется relay. В MVP он
  присутствует на устройстве, чтобы подписать `DeviceCredential`; «offline»
  означает «не участвует в сессиях», а не «физически отделён».
- Потеря seed и пароля (если OPAQUE включён) = потеря аккаунта. Это
  осознанная цена анонимности.

### 3.2 Account

- `account_id`: 16 байт, производная от seed через HKDF
  (`aegis-account-id-v2`), не от ника/телефона/email. Это позволяет
  восстановить `account_id` из seed-фразы и не хранить его только на
  устройстве.
- Публичный account bundle: `account_id`, `AIK` pub, подпись `AIK` над
  канонической сериализацией.
- Глобального ника нет. Отображаемое имя — локальное, передаётся только
  E2EE-контактам; оно не уникально и не является идентификатором.
- Поиска пользователей нет. Только инвайт.
- `AIK` подписывает `DeviceCredential` и список устройств.
- OPAQUE-аккаунт — **опциональный** (см. §3.6). По умолчанию работает
  seed-only; без OPAQUE серверного аккаунта нет.

### 3.3 Device

- `device_id`: 16 случайных байт.
- Каждое устройство имеет свой `DIK` (Curve25519, XEdDSA), ML-KEM prekey и
  libsignal prekeys.
- `DeviceCredential`:
  `account_id || device_id || device_pub || device_kem_pub || created_at ||
  expiry || capabilities`, подпись `AIK` (XEdDSA).
- Список устройств — подписан `AIK`; изменение требует подтверждения
  существующего устройства. В MVP одно устройство; multi-device — Phase 4.
- Сообщение шифруется на каждое активное устройство получателя.
- Серверной истории сообщений нет.

### 3.4 Invite

URI: `aegis://invite/v2/<base64url(CBOR)>` + QR.

Поля:

| Поле | Размер | Смысл |
|---|---|---|
| `version` | 2 | Версия протокола |
| `account_id` | 16 | Идентификатор аккаунта |
| `account_pub` | 32 | `AIK` pub (Curve25519) |
| `device_id` | 16 | Устройство |
| `device_pub` | 32 | `DIK` pub (Curve25519) |
| `device_credential` | var | Подпись `AIK` над устройством |
| `prekey_bundle` | var | SPK/OPK/PQPK + подписи `DIK` |
| `inbox_id` | 16 | Анонимный адрес очереди |
| `relay_hints` | var | 2–3 relay URL/onion |
| `created_at` | 8 | Unix seconds |
| `expires_at` | 8 | Unix seconds |
| `signature` | 64 | XEdDSA `DIK` над canonical bytes |

Правила:

- Получатель проверяет `device_credential` по `account_pub`, подпись инвайта
  по `device_pub`, подписи prekeys по `device_pub`.
- Просроченный/подделанный инвайт отвергается.
- `.onion` адреса не резолвятся через системный DNS.
- Никаких `127.0.0.1`, `169.254.169.254`, приватных подсетей и `userinfo`
  в relay hints.
- Инвайт — это **контактная карточка**, а не одноразовый ресурс. `max_uses`
  убран: relay не может enforcement'ить one-time без отдельного реестра
  инвайтов. Если one-time ссылки понадобятся позже — это отдельный дизайн с
  relay-side state и ADR.
- `read_token` в инвайт **не входит**. Получатель хранит его у себя;
  отправитель знает только `inbox_id`.
- Для offline-обмена QR можно показать лично; ссылка — только если удобно.

### 3.5 Safety number

- `safety_number = SHA-256("aegis-safety-v2" || account_pub || device_pub ||
  device_kem_pub)`.
- Показывать 60 цифр / QR; сравнивать при первом контакте.
- При смене любого ключа — предупреждение и повторная верификация.
- Key transparency (append-only log) — позже, не в MVP.

### 3.6 OPAQUE-аккаунт (opt-in)

OPAQUE **не заменяет** seed и не аутентифицирует сообщения. Это
опциональный сервис восстановления и синхронизации списка устройств.

- По умолчанию выключен; seed-only работает без сервера.
- Включение: пользователь задаёт пароль; клиент выполняет OPAQUE
  registration (RFC 9807) с `credential_identifier = account_id`.
  Сервер хранит OPAQUE registration record и параметры Argon2id; пароль
  никогда не видит.
- После login клиент получает OPAQUE `export_key`; из него через HKDF
  выводится ключ шифрования seed-backup. Seed шифруется
  XChaCha20-Poly1305 и загружается на account service. Сервер видит только
  `account_id`, ciphertext, версию и timing.
- Account service также может хранить подписанный `AIK` список устройств.
  Список проверяется по `AIK`; сервер не может его подделать. У списка и
  seed-backup есть монотонная версия; клиент отвергает rollback.
- Пароль сбрасывается только seed-фразой. Если потеряны и seed, и пароль —
  аккаунт потерян. Это честно написано в UI.
- OPAQUE login + seed-backup даёт полный контроль над аккаунтом. Device list
  — это UX/defense-in-depth, а не криптографический барьер против
  компрометации пароля и seed-backup: злоумышленник с ними может
  восстановить seed и добавить устройство. Это residual risk.
- Парольная политика (как Q-2): минимум 12 символов, не менее 3 заглавных,
  строчные, цифры, спецсимволы, проверка энтропии; Argon2id; rate limit/PoW.
  OPAQUE защищает от plaintext-утечки пароля и pre-computation, но
  скомпрометированный account service всё равно может позволить offline
  guessing против слабого пароля. Поэтому сильный пароль обязателен.
- Account service отделён от relay и OHTTP gateway. Если оператор тот же,
  появляется корреляция по timing; это residual risk, а не «нулевое
  знание».
- API account service (все вызовы только TLS 1.3 + OHTTP/Tor):
  `POST /v1/opaque/register`, `POST /v1/opaque/login`,
  `PUT /v1/account/seed`, `GET /v1/account/seed`,
  `GET /v1/account/devices`. Одинаковые ошибки, no logs, no PII.

## 4. Prekeys и установка сессии

### 4.1 Prekey bundle

| Поле | Смысл |
|---|---|
| `bundle_version` | Версия формата |
| `device_id` | Устройство |
| `spk_id` + `spk_pub` | Signed prekey X25519 |
| `spk_sig` | XEdDSA подпись `DIK` |
| `opk_id` + `opk_pub` | One-time prekey X25519 (может отсутствовать) |
| `pqpk_id` + `pqpk_pub` | ML-KEM encapsulation key |
| `pqpk_sig` | XEdDSA подпись `DIK` |
| `expires_at` | Срок жизни |

- Bundle подписан `DIK`; получатель проверяет подпись.
- OPK расходуется один раз; если закончились — SPK-only (слабее,
  логируется в UI как «сниженная защита»).
- Prekey bundle публикуется на key server; fetch через OHTTP/Tor.
- Key server не должен связывать fetch с аккаунтом; OHTTP gateway отделён.

### 4.2 PQXDH

Следуем опубликованной спецификации Signal PQXDH и реализации libsignal.
Не изобретаем свой комбинатор и не добавляем поля в transcript libsignal.

Обозначения:

- Alice: `DIK_A`, `EK_A`.
- Bob: `DIK_B`, `SPK_B`, `OPK_B`, `PQPK_B`.

Вычисления (как в libsignal):

```
DH1 = DH(DIK_A, SPK_B)
DH2 = DH(EK_A, DIK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)        # если OPK есть
KEM = ML-KEM-Encaps(PQPK_B)
SK  = HKDF(DH1 || DH2 || DH3 || DH4 || KEM || transcript)
```

- `transcript` — ровно тот, что задаёт libsignal: версия, identity keys,
  prekey IDs, ciphersuite. Мы не добавляем туда `account_id`/`device_id`;
  привязка аккаунта идёт через подписанный `DeviceCredential` и sender cert
  внутри E2EE-сообщения.
- Bob выполняет симметричные операции своими приватными ключами.
- Результат `SK` инициализирует Double Ratchet; Alice — инициатор.
- Все ключи проверяются на нули/совпадения; ошибка — fail closed.
- Реализация: `libsignal-protocol` с PQXDH, pinned commit. Если выбранная
  версия libsignal не содержит PQXDH, нельзя писать свой PQXDH: выбирается
  audited эквивалент через ADR.
- Параметр ML-KEM берём из libsignal; не смешиваем 768/1024 в одном
  протоколе.

### 4.3 Double Ratchet

- Использовать libsignal session, не писать свой.
- DH ratchet при получении нового public key.
- Пропущенные ключи: максимум 1000; старые удаляются; слишком большое
  расхождение — reject.
- Replay: отвергать повторный `(dh_pub, msg_num)`.
- Ratchet header находится внутри E2EE-конверта; relay его не видит.
  Отдельный «header encryption» слой не изобретаем. Если libsignal не
  предоставляет такое свойство, фиксируем это в ADR и не имитируем.
- Outer envelope (`inbox_id`, bucket, version) — routing metadata. Получатель
  сверяет их с копией внутри аутентифицированного plaintext (sender cert /
  content AAD). Не добавляем свой AAD в libsignal, если библиотека этого не
  поддерживает.
- Nonce: генерируется библиотекой; **никогда** не переиспользовать.
- Ключи и промежуточные значения — в `zeroize`/`secrecy`.
- Ошибка тега/подписи — не удалять отложенные ключи до успешной проверки.

### 4.4 Паддинг и timing

- Паддинг **до** шифрования, внутри AEAD.
- Buckets: 256, 1024, 4096, 16384, 65536 байт.
- Внутри bucket: `u16 length || plaintext || zero padding`.
- Внешний размер всегда ровно bucket; открытой длины нет.
- Случайная задержка 0–5 с; батчинг; cover traffic (dummy-пакеты того же
  размера).
- Не логировать размеры/время на сервере.

## 5. Blind envelope и relay

### 5.1 Внешний конверт

Relay видит только это:

| Поле | Размер | Смысл |
|---|---|---|
| `version` | 2 | Версия |
| `inbox_id` | 16 | Анонимный адрес получателя |
| `token_id` | 16 | Одноразовый blind token |
| `bucket` | 4 | 256/1024/4096/16384/65536 |
| `ciphertext` | bucket | Double Ratchet message |

Нет: sender ID, timestamp, content type, filename, group ID, IP-лога.
`token_id` — 16-байтный handle; полный VOPRF token передаётся в отдельном
заголовке, не логируется. `msg_id` для `DELETE` назначает relay при приёме
конверта; клиент получает его в ответе на чтение.

### 5.2 Внутренний plaintext

После расшифровки Double Ratchet получатель видит:

```
sender_cert:
  account_id, device_id, device_pub, account_pub,
  device_credential, expires_at, signature (DIK)
content_type: text | file_manifest | group_mls | control
content: bytes
routing: inbox_id, bucket, protocol_version
padding: zero bytes
```

- `sender_cert` подписан `DIK`; `device_credential` подписан `AIK`.
- Получатель проверяет подпись, expiry, `account_pub` из инвайта/safety
  number и совпадение `routing` с outer envelope.
- Relay никогда не видит `sender_cert`.
- Для первого сообщения сертификат позволяет получателю понять, кто пишет,
  не раскрывая отправителя relay.

### 5.3 Inbox

- `read_token`: 32 байта, выводится из seed и `device_id`:
  `HKDF(seed, "aegis-inbox-token-v2" || device_id)`.
- `inbox_id = SHA-256("aegis-inbox-id-v2" || read_token)[0..16]`.
- Relay проверяет `SHA-256("aegis-inbox-id-v2" || presented_token)[0..16] ==
  inbox_id` за константное время. **Регистрация inbox не нужна**; отдельного
  `POST /v1/inbox` нет.
- Sender знает только `inbox_id`; он не может вывести `read_token`
  (preimage resistance) и не может читать чужую очередь.
- `read_token` передаётся только в `Authorization: Bearer` по TLS/OHTTP;
  никогда в URL, логах или QR.
- Relay хранит очередь по `inbox_id`; TTL 7 дней; максимум 1000 конвертов.
- После успешного чтения конверт удаляется; повторная доставка —
  at-least-once с client-side dedup.
- Стабильный `inbox_id` позволяет relay видеть объём/timing. Для MVP это
  приемлемо при Tor + cover traffic; позже — per-contact inbox ID.
- DoS: любой, кто знает `inbox_id`, может заполнить очередь. Защита —
  квоты, rate limit, blind tokens; остаточный риск записан в threat model.
- Panic/duress: устройство генерирует новый `read_token`/`inbox_id`,
  старые инвалидируются; контактам нужен новый инвайт.

### 5.4 Blind tokens

- VOPRF (RFC 9497) или Privacy Pass; blind signature.
- Клиент получает токены через `POST /v1/token`, решив PoW.
- Токен одноразовый; relay не может связать выдачу и использование.
- PoW difficulty адаптивная; минимум 16 бит, максимум 32. (Старый минимум
  1 бит был ошибкой: он не защищал от спама.)
- Без аккаунта, email, телефона, IP-лога.
- Токены можно получить через OHTTP/Tor, отдельно от отправки.
- OPAQUE-аккаунт не используется для токенов и не связывается с ними.

### 5.5 Relay API

Все API — только TLS 1.3 + OHTTP/Tor. Никакого plain HTTP.

| Метод | Путь | Смысл |
|---|---|---|
| `POST` | `/v1/token` | Выдать blind tokens после PoW |
| `POST` | `/v1/envelope` | Положить конверт в inbox |
| `GET` | `/v1/inbox/{inbox_id}` | Забрать конверты (`Authorization: Bearer <read_token>`) |
| `DELETE` | `/v1/inbox/{inbox_id}/{msg_id}` | Подтвердить получение (`Authorization`) |
| `GET` | `/v1/relay` | Подписанный descriptor relay |

Правила:

- RAM-only; никаких дисков/логов; `peer_addr()` не читать.
- TTL, quota, rate limit; ответы не раскрывают existence/timing.
- Одинаковые ответы по времени/размеру для «есть/нет».
- Никаких метрик с PII; только агрегированные счётчики без идентификаторов.
- Relay descriptor подписан Ed25519; клиент пиннит ключ; rotation — через
  подписанный directory и overlap-период.
- Ошибки: для пустого/несуществующего inbox — одинаковый `200`/`204` с
  пустым списком; `429` только при rate limit; без деталей. Не логировать
  `inbox_id` и токены.

### 5.6 Federation

- Получатель выбирает 2–3 relay и указывает их в инвайте.
- Отправитель загружает конверт на каждый relay.
- Relay-to-relay пересылки в MVP нет (меньше метаданных).
- Позже — blind relay: входной узел не знает получателя, выходной не знает
  отправителя; только с audited дизайном и тестами.
- Один relay = одна точка отказа; несколько — устойчивость.
- Account service, key server, OHTTP gateway и blob store — отдельные роли;
  нельзя складывать их в один процесс «для удобства».

## 6. P2P (после MVP)

- Каждое устройство поднимает Arti onion service с эфемерным адресом.
- Контакт получает onion-адрес через инвайт/rendezvous.
- Транспорт: QUIC поверх Tor + Noise XX (или TLS 1.3).
- Если оба онлайн — сообщение идёт напрямую; иначе relay.
- Прямой IP никогда не используется; только onion.
- Мобильный фон: P2P только на переднем плане; в фоне — relay.
- P2P не заменяет relay: это ускорение и дополнительная устойчивость.
- **P2P не входит в MVP** (решение владельца 2026-10-30); начинается после
  стабилизации relay.

## 7. Группы (beta)

- MLS RFC 9420 через `openmls`.
- Ciphersuite: стандартный
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`; PQ hybrid — после
  стабилизации.
- `group_id`: 32 случайных байта; relay его не видит.
- Члены: identity keys; add/remove через MLS Commit; Welcome для нового.
- Для группы ≤ 20: отправитель шифрует MLS-сообщение один раз, затем
  оборачивает его в 1:1 Double Ratchet для каждого члена. Relay видит
  отдельные конверты, не группу.
- Для больших групп позже: opaque group inbox; relay видит группу, но не
  содержимое; это компромисс по метаданным.
- Групповые файлы — через blob store; манифест в MLS-сообщении.
- Сервер не хранит состояние группы.
- Смена состава группы → новое сравнение safety number для добавленных
  участников; key-change warning.

## 8. Файлы

- `file_key`: 32 случайных байта.
- Шифрование: XChaCha20-Poly1305; nonce 24 байта на чанк.
- Чанк: 1 MiB; паддинг до 1 MiB; AAD = `file_id || chunk_index ||
  total_chunks`.
- `blob_id`: 32 случайных байта; без dedup (dedup leaks).
- Upload: 3 независимых blob store; VOPRF tokens; Tor/OHTTP.
- Manifest: `file_id`, `file_key`, plaintext size, chunk IDs, SHA-256,
  chunk count. Manifest уходит в E2EE-сообщении.
- Имя файла не передаётся; EXIF/GPS/ICC/thumbnails удаляются до
  шифрования.
- TTL 7 дней; max 100 MB в MVP; позже — P2P для больших файлов.
- Blob store видит только случайный ID, размер и timing; паддинг и cover
  traffic снижают утечку.

## 9. Локальное хранилище

- SQLCipher; `DB_KEY` 32 байта.
- `DB_KEY` оборачивается KEK:
  - PIN → Argon2id → KEK;
  - Android Keystore/StrongBox;
  - desktop OS keyring;
  - iOS Secure Enclave позже.
- Нет автоматических облачных бэкапов ОС. Экспорт истории — **только явный**
  зашифрованный файл, ключ из пароля через Argon2id (решение владельца
  2026-10-30). OPAQUE seed-backup — это не история чата, а только seed.
- Duress PIN: wipe ключей/БД; decoy-профиль — опционально, с
  предупреждением.
- Auto-lock; запрет скриншотов (Android FLAG_SECURE, iOS blur, desktop best
  effort); скрытие в recents.
- Ключи в `zeroize`/`secrecy`; никаких секретов в логах/ошибках/аналитике.
- Поиск по сообщениям — локальный, внутри зашифрованной БД.

## 10. Уведомления

- Android: UnifiedPush/self-hosted ntfy через Tor; generic payload без
  текста/имени; без FCM по умолчанию. Foreground service — опция.
- Desktop: долгоживущее Tor-соединение.
- iOS позже: APNs silent push; Apple видит device token/timing, не контент;
  пользователь может отключить. Это честно написано в UI.
- Push не содержит отправителя, текста, группы, размера.
- Метаданные push-провайдера: topic/device token и timing. Топик
  рандомный, per-device, ротируется; не переиспользуется между аккаунтами.

## 11. Исчезающие сообщения

- Таймер на клиенте; серверного копирования нет.
- Relay TTL 7 дней; после доставки — удаление.
- Получатель может сохранить/сфотографировать; это best effort.
- View-once — только UX-барьер, не криптографическая гарантия.

## 12. Abuse и жалобы

- Серверного сканирования контента нет.
- Клиентский block/report; rate limits, PoW, квоты; блокировка по inbox ID.
- Message franking **отложен**: сначала выбираем опубликованную схему и
  делаем ADR, а не изобретаем свою. В MVP — block/report с
  пользовательскими доказательствами.
- Прозрачная политика; никаких обещаний «модерации всего».
- App Store риск: Android — APK/F-Droid; iOS — позже.

## 13. Версионирование и crypto agility

- `protocol_version` (u16), `ciphersuite_id` (u16).
- Downgrade protection: версия в AAD/подписи; неизвестная версия — reject.
- Новые ciphersuites — через ADR, тесты, миграцию.
- Старые версии поддерживаются ограниченное время; deprecation policy.
- Никаких «тихих» изменений формата.
- Invite v2, envelope v2; v1 несовместим и не принимается.

## 14. Тест-векторы и проверка

- RFC 8439 (ChaCha20-Poly1305), RFC 5869 (HKDF), RFC 2104 (HMAC),
  FIPS 180-4 (SHA-256), RFC 8032 (Ed25519), RFC 7748 (X25519),
  FIPS 203 (ML-KEM).
- XEdDSA — векторы libsignal; PQXDH/Double Ratchet — векторы libsignal или
  опубликованные.
- OPAQUE — RFC 9807; Argon2id — RFC 9106; OHTTP — RFC 9458; VOPRF —
  RFC 9497; MLS — RFC 9420 + векторы OpenMLS.
- Cross-implementation: Rust ↔ Kotlin ↔ Swift.
- Fuzzing всех парсеров; property tests; formal analysis (ProVerif/Tamarin).
- Внутренний red team до public alpha; внешний аудит до 1.0.

## 15. Открытые вопросы

1. libsignal: vendored subtree или git dependency с pinned commit? Как
   собирать на Android?
2. ML-KEM параметр: ровно тот, что в libsignal, или 768? Не смешивать.
3. Стабильный inbox ID в MVP или per-contact сразу? Сейчас — стабильный.
4. Key transparency сейчас или после аудита?
5. Mixnet (Nym/Loopix) как paranoid mode или достаточно Tor?
6. Android push: UnifiedPush/ntfy или свой WebSocket через Tor?
7. Кто оператор account service и OHTTP gateway? Как не связать их с relay?
8. Кто независимый сборщик/аудитор при соло-разработке?
9. Какой бюджет на аудит и когда его искать?
10. Юрисдикция и юридическая форма проекта.
