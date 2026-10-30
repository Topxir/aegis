# Aegis Architecture v2 (APPROVED rev.2)

**Статус: УТВЕРЖДЕНО владельцем 2026-10-30. Дата: 2026-10-30.**
Ревизия 2: libsignal XEd25519, opt-in OPAQUE account service, P2P после MVP,
группы ≤ 20, public alpha после внутреннего red team, только явный экспорт.

## 1. Целевая картина

```
┌──────────────┐        Tor / OHTTP        ┌──────────────┐
│  Client A    │ ────────────────────────► │  Relay 1..3  │
│  Rust core   │                           │  RAM-only    │
│  Android/    │ ◄──────────────────────── │  no logs     │
│  Desktop     │                           └──────────────┘
│              │        P2P onion (после MVP)      ▲
│              │ ◄───────────────────────────────┐ │
└──────┬───────┘                                 │ │
       │ TLS 1.3 / OHTTP                         │ │
       ├───────────────┬─────────────────┬───────┘ │
       ▼               ▼                 ▼         │
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│ OHTTP Gateway│ │ Account svc  │ │  Blob store  │ │
│ separate op  │ │ OPAQUE + seed│ │  encrypted   │ │
└──────────────┘ └──────────────┘ └──────────────┘ │
       │                                             │
       ▼                                             │
┌──────────────┐                                     │
│  Key server  │                                     │
│  prekeys     │                                     │
└──────────────┘                                     │
```

Клиент не доверяет ни одному серверу. Relay — «слепой почтальон»: видит
`inbox_id`, размер, timing; не видит отправителя, содержимое, группу.
Blob store видит случайные ID и размеры. Key server видит публичные prekeys.
Account service видит `account_id`, OPAQUE-запись, зашифрованный seed-backup
и device list; не видит сообщения. OHTTP gateway видит IP, но не содержимое
запроса; relay видит запрос, но не IP. Это разделение ролей принципиально.

## 2. Компоненты

| Компонент | Язык | Ответственность |
|---|---|---|
| `aegis-core` | Rust | Крипто-протокол, identity, storage, groups, files |
| `aegis-ffi` | Rust + UniFFI | Единая граница для Android/Desktop/iOS |
| `aegis-relay` | Rust | Очереди, blind tokens, TLS 1.3, OHTTP, no logs |
| `aegis-account` | Rust | OPAQUE RFC 9807, encrypted seed-backup, signed device list |
| `aegis-blob` | Rust | Шифрованные блобы, TTL, квоты |
| `aegis-directory` | Rust | Подписанные relay/account descriptors, M-of-N |
| `aegis-launcher` | Rust | Мастер своего relay/account (VPS/Docker/onion) |
| `aegis-ui-android` | Kotlin/Compose | UI, Keystore, UnifiedPush |
| `aegis-ui-desktop` | Rust native GUI | UI, OS keyring, Tor |
| `aegis-ui-ios` | SwiftUI | Позже, после стабилизации ядра |
| `aegis-tools` | Rust | CLI, test harness, fuzzing, migration |

### 2.1 `aegis-core`

- `#![forbid(unsafe_code)]`.
- Никаких самописных примитивов.
- Модули:
  - `crypto`: обёртки над audited crates; только типы, никакой логики
    протокола;
  - `identity`: seed, `AIK`/`DIK` (libsignal XEdDSA), invites, safety
    numbers, device list, optional OPAQUE client;
  - `protocol`: libsignal PQXDH/Double Ratchet, blind envelope, groups,
    files;
  - `storage`: SQLCipher, migrations, wipe;
  - `transport`: TLS/QUIC/Tor/OHTTP, relay API, account API, P2P позже;
  - `notifications`: generic push, no content.
- Публичное API — только через `aegis-ffi`.
- Все ошибки типизированы; никаких `unwrap`/`panic` на внешних данных.

### 2.2 `aegis-ffi`

- UniFFI bindings для Kotlin и Swift; desktop может использовать Rust
  напрямую, но через тот же фасад.
- UI не видит ключи, ratchet state, SQLCipher key.
- FFI отдаёт только высокоуровневые события: `send_text`, `send_file`,
  `incoming_message`, `verify_safety_number`, `panic_wipe`,
  `enable_opaque_recovery`.
- Секреты не пересекают FFI в виде строк; только opaque handles.

### 2.3 `aegis-relay`

- Rust, `axum`/`hyper` + `rustls`.
- RAM-only очереди; TTL; квоты; VOPRF tokens; PoW.
- Inbox ID выводится из `read_token`; отдельной регистрации inbox нет.
- Никаких логов, `peer_addr()` не читается.
- OHTTP endpoint; отдельный gateway.
- Метрики — только агрегированные, без PII.
- Docker: read-only FS, no logging driver, no persistent volume.
- Descriptor подписан Ed25519; клиент пиннит ключ.
- Не хранит: IP, аккаунты, контактный граф, историю, содержимое.

### 2.4 `aegis-account`

- Rust, `rustls` + `opaque-ke` + `argon2`.
- OPAQUE registration/login; пароль не хранится и не логируется.
- Хранит OPAQUE registration record, зашифрованный seed-backup и
  подписанный `AIK` device list. Не хранит сообщения, контакты, историю.
- Persistent storage только для этих записей; шифрование at rest, no logs,
  минимальные метаданные. В отличие от relay, account service не RAM-only:
  иначе восстановление невозможно.
- Отделён от relay и OHTTP gateway; иначе timing-корреляция.
- Rate limit/PoW; одинаковые ошибки; no IP logs.
- Descriptor подписан Ed25519; клиент проверяет.

### 2.5 `aegis-blob`

- Шифрованные блобы; случайный `blob_id`; TTL 7 дней.
- 3 реплики в разных юрисдикциях; без dedup.
- VOPRF tokens; rate limits; no logs.
- Max blob size 1 MiB (chunk); max file 100 MB в MVP.
- Удаление по TTL; нет «вечного» хранения.

### 2.6 `aegis-directory`

- Подписанный список relay/account: URL/onion, Ed25519 pubkey, юрисдикция,
  uptime, версия.
- M-of-N подписи; revocation list.
- Клиент проверяет подпись, не доверяет серверу.
- Никаких «галочек», которые сервер рисует сам.

### 2.7 `aegis-launcher`

- Генерирует Docker Compose/cloud-init/systemd для своего relay/account.
- Onion-режим: hidden service, без статического IP.
- Прямой режим: только с TLS 1.3 и предупреждением.
- Не встраивать чужие статические IP как «официальные».

## 3. Границы доверия

| Граница | Доверяем | Не доверяем |
|---|---|---|
| Клиент ↔ relay | TLS 1.3 + pinning; Tor/OHTTP | Relay, сеть, хостинг |
| Клиент ↔ account | OPAQUE + TLS 1.3/OHTTP | Account service, сеть |
| Клиент ↔ blob | TLS 1.3; шифрование файла | Blob store, сеть |
| Клиент ↔ key server | Подписи prekeys; OHTTP | Key server, сеть |
| Клиент ↔ push | Generic payload | Apple/Google, push-провайдер |
| Клиент ↔ OS | Sandbox, keystore | Malware, root, физический доступ |
| Сборка ↔ релиз | Reproducible builds, подписи | CI, зависимости, maintainer |

## 4. Основные сценарии

### 4.1 Онбординг

1. Генерация seed (32 байта) и 24 слов (опционально).
2. Деривация `AIK`/`DIK` (Curve25519, XEdDSA) и ML-KEM.
3. Создание `account_id`, `device_id`, `DeviceCredential`, prekeys.
4. Выбор 2–3 relay из directory.
5. Показ QR-инвайта и safety number.
6. Опционально: включение OPAQUE-восстановления (пароль, seed-backup).
7. Никакого глобального ника/email/телефона.

### 4.2 Добавление контакта

1. Сканирование QR/инвайта v2.
2. Проверка `DeviceCredential` по `account_pub`, подписи инвайта по
   `device_pub`, срока.
3. Fetch prekey bundle через OHTTP/Tor.
4. Проверка подписей prekeys `DIK`.
5. PQXDH → Double Ratchet.
6. Сравнение safety number (QR/60 цифр).
7. Первое сообщение через relay; P2P — после MVP.

### 4.3 Отправка 1:1

1. Pad plaintext до bucket.
2. libsignal Double Ratchet encrypt.
3. Внутрь — sender cert + routing + content.
4. Outer blind envelope: inbox_id + token + ciphertext.
5. Upload на 2–3 relay через Tor/OHTTP.
6. Получатель poll'ит inbox с read token, расшифровывает, проверяет cert и
   routing.
7. Relay удаляет после ack; TTL.

### 4.4 Файл

1. Strip EXIF/ICC/thumbnails.
2. Random file key; XChaCha20-Poly1305; chunks 1 MiB; pad.
3. Upload 3 blob stores; random IDs; VOPRF tokens.
4. Manifest в E2EE-сообщении.
5. Получатель скачивает через Tor/OHTTP, проверяет SHA-256, расшифровывает.
6. TTL 7 дней; локальное сохранение — по желанию.

### 4.5 Группа (beta)

1. Создатель генерирует `group_id`, MLS group.
2. Приглашения — 1:1 сообщения с MLS Welcome.
3. Сообщение: MLS encrypt → pairwise wrap для каждого члена.
4. Relay видит отдельные конверты, не group_id.
5. Add/remove — MLS Commit; epoch rotation.
6. Max 20 в бете; позже — opaque group inbox.

### 4.6 Восстановление (opt-in OPAQUE)

1. Пользователь включает OPAQUE, задаёт сильный пароль.
2. OPAQUE registration; сервер хранит verifier, не пароль.
3. Seed шифруется ключом из OPAQUE export key; ciphertext на account service.
4. На новом устройстве: OPAQUE login → export key → decrypt seed →
   re-derive keys → device list.
5. Если пароль забыт — seed-фраза. Если потеряны и seed, и пароль —
   аккаунт потерян.
6. История сообщений не восстанавливается; только явный экспорт.

### 4.7 Паника / duress

1. Panic PIN → wipe keys/DB, stop services, clear UI state.
2. Duress PIN → decoy profile или wipe (по выбору).
3. Relay inbox rotation; старые токены инвалидируются.
4. OPAQUE seed-backup можно удалить с account service (опция).
5. Никаких логов о причине wipe.

## 5. Деплой

- 3 relay в разных юрисдикциях; минимум 2 оператора.
- Tor onion service для каждого relay; прямой TLS — опция.
- OHTTP gateway — отдельный оператор/сервер.
- Account service — отдельно от relay; persistent encrypted storage только
  для OPAQUE/seed/device list; no logs.
- Blob store — отдельно от relay.
- Relay: нет persistent volumes; RAM-only; read-only root FS.
- Секреты — через env/secret manager; не в git.
- Мониторинг — без PII; только health/агрегаты.
- Бэкапы relay не нужны: очереди TTL и RAM-only. Account service — только
  зашифрованные записи, без plaintext.
- DDoS: PoW, rate limits, anycast/прокси, но без логирования IP.

## 6. Сборка и supply chain

- Rust stable, pinned toolchain; `Cargo.lock` в git.
- libsignal pinned commit/hash; vendored или git dependency — ADR.
- `cargo deny`, `cargo audit`, `cargo vet`; SBOM (CycloneDX).
- `cargo fuzz` для парсеров; `proptest` для инвариантов.
- Reproducible builds: deterministic flags, `SOURCE_DATE_EPOCH`,
  `--remap-path-prefix`; несколько независимых сборщиков.
- Подписи релизов (Sigstore/cosign или minisign); SHA-256 manifest.
- CI: GitHub Actions с минимальными правами; pinned actions; no secrets
  в PR; branch protection; signed commits.
- Android: подпись release key; F-Droid metadata; direct APK.
- Desktop: подписанные бинарники; checksums.
- iOS: TestFlight/App Store позже; честный риск отказа.
- Public alpha — после внутреннего red team, с меткой «unaudited».
  Внешний аудит — до 1.0.

## 7. Структура репозитория (целевая)

```
aegis/
  Cargo.toml
  crates/
    aegis-core/
      src/crypto/
      src/identity/
      src/protocol/
      src/storage/
      src/transport/
      src/groups/
      src/files/
      src/account/
    aegis-ffi/
    aegis-relay/
    aegis-account/
    aegis-blob/
    aegis-directory/
    aegis-launcher/
    aegis-tools/
  apps/
    aegis-android/
    aegis-desktop/
    aegis-ios/          # позже
  docs/
    security-reset/
    contracts/
    tasks/
    reports/
  scripts/
  builds/
```

- `apps/` не входит в Cargo workspace; собирается отдельно.
- `builds/` — только релизные артефакты; не коммитить отладочные.
- `docs/contracts/` обновляется при изменении API.
- `docs/security-reset/` — этот план; после утверждения переносится в
  `docs/` как основной threat model/protocol.

## 8. Ветки и релизы

- Репозиторий приватный до внутреннего red team.
- `main` protected; PR + review; signed commits.
- `security/t0017-plan` — только документы.
- Feature-ветки короткие; без долгоживущей приватной ветки.
- После внутреннего red team — public alpha с меткой «unaudited»; тег
  `v0.1.0-alpha.1`.
- Внешний аудит — до 1.0; после него можно убрать метку «unaudited».
- Никаких секретов в истории; gitleaks в CI.
- Лицензия AGPL-3.0-or-later.

## 9. Зависимости: политика

Для каждой новой зависимости — ADR:

- зачем нужна;
- лицензия (AGPL-совместимость);
- кто аудировал/поддерживает;
- альтернативы;
- версия/хэш/commit;
- размер/сборка на Android;
- известные CVE;
- план обновления.

Минимум зависимостей, но **лучше audited библиотека, чем свой код**.
Приоритет: libsignal/OpenMLS/rustls/arti/opaque-ke/argon2/sqlcipher/ohttp/
voprf. Пользовательская идентичность — libsignal XEd25519; Ed25519 — только
инфраструктура. Конкретные версии, лицензии и альтернативы — в
[`docs/adr/`](../adr/README.md).

## 10. Что удаляем/не используем

- Самописные SHA-256/HMAC/HKDF/ChaCha20/Poly1305/AEAD/ratchet/OPAQUE.
- `DirectTls` как ярлык без TLS.
- Plain HTTP relay.
- Статические IP как «официальные» по умолчанию.
- Самописный «MLS-style» epoch secret.
- Самописный «PQXDH combiner» без X25519/ML-KEM.
- Webview-based desktop UI (XSS-риск); native Rust GUI.
- FCM по умолчанию; сторонние SDK; аналитику; crash-репорты.
- Блокчейн/IPFS для сообщений.
- Звонки/камеру/микрофон в MVP.
- Автоматический cloud backup; только явный экспорт.
- Собственный message franking до выбора опубликованной схемы.
- Одноразовые инвайты без relay-side реестра.

## 11. Открытые архитектурные вопросы

1. libsignal vendored или git dependency с pinned commit?
2. Desktop GUI: `slint`, `iced` или `egui`? (native, без webview)
3. Android: UniFFI + Compose; как хранить ключи в StrongBox?
4. Relay: `axum` + `rustls` + `ohttp`; нужен ли QUIC?
5. P2P: Arti onion + QUIC; как делать rendezvous? (после MVP)
6. Blob store: файловая система vs S3-совместимое; как обеспечить no logs?
7. Account service: отдельный сервис/оператор; как не связать с relay?
8. OHTTP gateway: кто оператор, как не связать с relay?
9. Мониторинг без PII: какие метрики вообще допустимы?
10. Юрисдикция и юридическая форма.
