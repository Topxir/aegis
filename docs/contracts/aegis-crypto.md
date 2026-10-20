# Контракт: aegis-crypto
Версия контракта: 0.1

## Ответственность
Предоставляет строго типизированные, безопасные по памяти (`zeroize`) обёртки над проверенными криптографическими библиотеками (D-0012):
- Хэширование и быстрый KDF (`BLAKE3`, `HKDF-SHA256`);
- Парольный KDF (`Argon2id`);
- Аутентификация с нулевым разглашением пароля (`OPAQUE`, RFC 9807 на Ristretto255);
- Симметричное аутентифицированное шифрование (`ChaCha20-Poly1305`, `XChaCha20-Poly1305`);
- Цифровые подписи (`Ed25519` со строгой проверкой `verify_strict`);
- Гибридный пост-квантовый обмен ключами (`Aegis-PQXDH`: `X25519` + `ML-KEM-768` FIPS 203);
- Двойной храповик сессионного шифрования (`Double Ratchet`);
- Генерация и проверка криптографических пазлов Anti-DDoS (`BLAKE3 Proof-of-Work`);
- Слепые подписи для анонимных донат-токенов (`SupporterPass` / Privacy Pass).

Модуль **не знает** о сети, базе данных, файловой системе или UI.

## Публичное API (функции, типы, ошибки)

### Секретные буферы и ключи (все реализуют `Zeroize` и `ZeroizeOnDrop`)
- `SecretBytes<const N: usize>` — фиксированный секретный буфер в RAM, запрещающий `Display`, прозрачный `Debug` и `Clone` без явного вызова.
- `SymmetricKey256` (`SecretBytes<32>`) — 256-битный ключ для AEAD / KDF.
- `Ed25519KeyPair`, `Ed25519PublicKey([u8; 32])`, `Ed25519Signature([u8; 64])`.
- `X25519KeyPair`, `X25519PublicKey([u8; 32])`.
- `MlKem768KeyPair`, `MlKem768PublicKey([u8; 1184])`, `MlKem768Ciphertext([u8; 1088])`.
- `HybridPreKeyBundle` — связка ключей получателя (`Ed25519` identity + подписанный `X25519` SPK + подписанный `ML-KEM-768` PQSPK + опциональный одноразовый пре-ключ).
- `RatchetState` — состояние сессии Double Ratchet.
- `PowChallenge`, `PowSolution` — структуры адаптивного Proof-of-Work.
- `BlindTokenRequest`, `BlindTokenSignature`, `SupporterPassToken` — типы слепых подписей.

### Основные функции
- `derive_key_argon2id(password: &[u8], salt: &[u8; 32], params: Argon2Params) -> Result<SymmetricKey256, CryptoError>`
- `hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<SymmetricKey256, CryptoError>`
- `blake3_keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32]`
- `aead_encrypt_xchacha20(key: &SymmetricKey256, nonce: &[u8; 24], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CryptoError>`
- `aead_decrypt_xchacha20(key: &SymmetricKey256, nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError>`
- `ed25519_sign(keypair: &Ed25519KeyPair, message: &[u8]) -> Ed25519Signature`
- `ed25519_verify_strict(pubkey: &Ed25519PublicKey, message: &[u8], sig: &Ed25519Signature) -> Result<(), CryptoError>`
- `ed25519_verify_m_of_n(trusted_keys: &[Ed25519PublicKey], threshold: usize, message: &[u8], signatures: &[(u8, Ed25519Signature)]) -> Result<(), CryptoError>`
- `pqxdh_initiate(our_identity: &X25519KeyPair, peer_bundle: &HybridPreKeyBundle) -> Result<(SymmetricKey256, PqxdhInitialMessage), CryptoError>`
- `pqxdh_respond(our_keys: &LocalHybridPreKeys, init_msg: &PqxdhInitialMessage) -> Result<SymmetricKey256, CryptoError>`
- `solve_pow_blake3(challenge: &PowChallenge) -> Result<PowSolution, CryptoError>`
- `verify_pow_blake3(challenge: &PowChallenge, solution: &PowSolution, server_pub: &Ed25519PublicKey) -> Result<(), CryptoError>`

### Ошибки (`CryptoError`)
- `InvalidSignature` — подпись Ed25519 или M-of-N не прошла строгую проверку.
- `AeadDecryptionFailed` — ошибка проверки MAC Poly1305 при расшифровке.
- `InvalidKeyLength` / `WeakKeyRejected` — некорректный размер ключа или точка малого порядка X25519.
- `KdfParameterError` — небезопасные параметры Argon2id/HKDF.
- `OpaqueProtocolError` — ошибка шага протокола OPAQUE.
- `PowVerificationFailed` — решение пазла не соответствует требуемой сложности или истёк срок пазла.
- `RngFailure` — отказ системного генератора случайных чисел (`OsRng`).

## Гарантии
1. **Отсутствие самописной криптографии:** используются только стандартизованные алгоритмы из D-0012.
2. **Очистка памяти (`Zeroize`):** все приватные ключи, общие секреты DH/KEM и расшифрованные буферы зануляются в памяти при `Drop`.
3. **Защита от тайминг-атак:** сравнение MAC и подписей выполняется за константное время (`subtle::ConstantTimeEq`).
4. **Fail Closed:** любая ошибка проверки подписи, тега Poly1305 или подгруппы кривой немедленно возвращает `Err(CryptoError)` без частичного возврата данных.

## Запрещено вызывающему
- Запрещено сериализовать приватные ключи в открытые строки (`String`), логировать их или клонировать за пределы `Zeroizing`-обёрток.
- Запрещено повторно использовать один и тот же `nonce` с одним и тем же ключом AEAD.
- Запрещено понижать параметры `Argon2Params` ниже минимального порога безопасности (`m >= 32 MiB`, `t >= 2`).

## Зависимости
- Внутренние модули Aegis: **нет** (базовый слой).
- Внешние крейты (D-0012): `argon2`, `blake3`, `hkdf`, `sha2`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `ml-kem`, `opaque-ke`, `zeroize`, `subtle`, `rand_core`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
