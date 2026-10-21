# Контракт: aegis-directory
Версия контракта: 0.1

## Ответственность
Управляет криптографическим доверием к серверам федерации, сертификатам официальной поддержки и ключам эмиссии анонимных донат-токенов (PLAN.md §6.3, D-0006, D-0010, D-0011):
- Хранение зашитых корневых публичных ключей фонда (`FoundationRootKeys`) и проверка пороговых подписей **M-of-N Ed25519** (`threshold >= 1`, плавный переход с `1-of-1` на `2-of-3`);
- Верификация подписанного каталога серверов и присвоение проверяемых уровней доверия:
  - **Официальный сервер (`Official ✓✓`)** — поднят и управляется проектом Aegis;
  - **Проверенный сервер (`Verified ✓`)** — прошёл аудит сборки (reproducible build hash), политику отсутствия логов и аптайм;
  - **Сервер сообщества (`Community`)** — пользовательский сервер без подписи фонда (отображается с честным предупреждением);
- Верификация сертификатов аккаунтов официальной поддержки (`SupportRoleCert ✓`), исключающая фишинг под видом техподдержки;
- Проверка подписанных списков отзыва (`RevocationList` / `CRL`) на случай компрометации сервера или ключа;
- Предоставление проверенных публичных ключей эмитента слепых токенов `SupporterPass` для модуля `aegis-identity`.

## Публичное API (функции, типы, ошибки)

### Типы
- `TrustBadge`:
  - `OfficialDoubleCheck` (`✓✓`)
  - `VerifiedSingleCheck` (`✓`)
  - `CommunityUnverified` (без галочки, с предупреждением)
- `MofNSignatureSet { threshold_required: u8, signatures: Vec<(u8, Ed25519Signature)> }`
- `DirectoryServerEntry { endpoint: String, onion_endpoint: Option<String>, server_pubkey: Ed25519PublicKey, badge: TrustBadge, binary_sha256: [u8; 32], issued_at: u64, expires_at: u64 }`
- `SignedDirectoryBundle { version: u64, published_at: u64, min_threshold: u8, servers: Vec<DirectoryServerEntry>, support_certs: Vec<SupportRoleCert>, revoked_pubkeys: Vec<RevokedEntry>, signatures: MofNSignatureSet }`
- `SupportRoleCert { role_id: String, support_signing_key: Ed25519PublicKey, support_kem_bundle: HybridPreKeyBundle, expires_at: u64, signatures: MofNSignatureSet }`
- `VerifiedServerInfo`, `VerifiedSupportCert` — типы-свидетели (type-state), которые можно создать **только** после успешной проверки M-of-N подписей и отсутствия в списке отзыва.

### Основные функции
- `verify_directory_bundle(raw_bundle_json_or_bin: &[u8], now_unix: u64, last_known_version: u64) -> Result<VerifiedDirectory, DirectoryError>`
- `verify_server_badge(directory: &VerifiedDirectory, server_pubkey: &Ed25519PublicKey, now_unix: u64) -> Result<TrustBadge, DirectoryError>`
- `verify_support_certificate(directory: &VerifiedDirectory, cert: &SupportRoleCert, now_unix: u64) -> Result<VerifiedSupportCert, DirectoryError>`
- `is_key_revoked(directory: &VerifiedDirectory, pubkey: &Ed25519PublicKey) -> bool`

### Ошибки (`DirectoryError`)
- `InsufficientValidSignatures { valid: usize, required: usize }` — количество валидных подписей от уникальных корневых ключей фонда меньше порога `M`.
- `RollbackAttackDetected { bundle_version: u64, last_seen: u64 }` — попытка подсунуть устаревшую версию каталога или списка отзыва.
- `CertificateExpired { expired_at: u64 }` — срок действия сертификата сервера или поддержки истёк.
- `KeyRevoked(Ed25519PublicKey)` — публичный ключ находится в подписанном списке отзыва (`CRL`).
- `MalformedDirectoryFormat` — ошибка десериализации структуры каталога.

## Гарантии
1. **Невозможность самопровозглашения галочки ✓ (PLAN.md §6.3):** ни один сервер и ни один пользователь не может сам выставить себе флаг `Official ✓✓` или `Support ✓`. Типы `VerifiedServerInfo` и `VerifiedSupportCert` не имеют публичных конструкторов вне модуля `aegis-directory` и создаются только после проверки пороговой подписи `M-of-N Ed25519`.
2. **Защита от отката версий (Anti-Rollback):** `verify_directory_bundle` отвергает любой каталог с `version < last_known_version`, предотвращая скрытие новых записей отзыва (`CRL`).
3. **Готовность к ротации ключей фонда (D-0011):** проверка изначально поддерживает массив корневых ключей и порог `M-of-N`.

## Запрещено вызывающему
- Запрещено отображать в UI значки `✓` или `✓✓` на основе текстового имени пользователя или непроверенного ответа сервера без вызова `verify_server_badge` / `verify_support_certificate`.
- Запрещено игнорировать ошибку `KeyRevoked` (**Fail Closed**).

## Зависимости
- Внутренние модули: `aegis-crypto`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
- `0.2` (2026-10-22, T-0011 / D-0019): Добавлено поле `static_ipv4: Option<[u8; 4]>` в `DirectoryServerEntry`, метод `BuiltInDirectory::direct_static_ip_entries()` и встроенные стартовые серверы со статическим IP без обязательного Tor.
