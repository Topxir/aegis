# Контракт: aegis-identity
Версия контракта: 0.1

## Ответственность
Управляет жизненным циклом учётных записей и локальной аутентификацией пользователя (PLAN.md §4, D-0002, D-0006, D-0010):
- Генерация случайных криптостойких анонимных ников (алиасов) в 1 клик;
- Валидация пароля по строгому стандарту безопасности (не менее 12 символов, >= 3 заглавных букв, строчные буквы, цифры, спецсимволы, проверка энтропии без внешних словарей с телеметрией);
- Вычисление обезличенного `login_id = KDF(nickname, server_salt)` и выполнение клиентских шагов протокола **OPAQUE** (регистрация и вход при переустановке);
- Управление цепочкой защиты ключа локальной БД (`DB_KEY`): двойное оборачивание через `KEK_password` (`Argon2id`) и аппаратный ключ `HardwareKeystore` под защитой **PIN** с аппаратным счётчиком попыток;
- Обработка **Duress-PIN** (принудительный PIN: тихое крипто-стирание боевых ключей или открытие ложного профиля);
- Контроль квоты мультиаккаунтов на устройстве (**до 3 профилей бесплатно**, 4-й и более — только при предъявлении валидного слепого токена `SupporterPass`);
- Шифрование и расшифровка облачного конверта синхронизации очередей (`AccountVault`) и опциональной фразы восстановления (24 слова BIP-39).

## Публичное API (функции, типы, ошибки)

### Типы
- `AccountSlotId(u8)` — индекс изолированного профиля на устройстве (`0..=2` бесплатно, `3+` с `SupporterPassToken`).
- `PasswordPolicyReport { is_valid: bool, length_ok: bool, uppercase_count: usize, has_lowercase: bool, has_digit: bool, has_special: bool, entropy_bits: f32 }`
- `LoginId([u8; 32])` — обезличенный идентификатор записи OPAQUE на сервере.
- `AccountVaultPayload` — структура синхронизируемого конверта (список односторонних очередей, ключей идентичности и настроек профиля).
- `UnlockOutcome` — результат ввода PIN:
  - `UnlockedNormal { slot_id: AccountSlotId, db_key: SymmetricKey256 }`
  - `TriggeredDuress { mode: DuressMode, decoy_db_key: SymmetricKey256 }`
- `HardwareKeystoreProvider` (trait) — абстракция над Android StrongBox/Keystore, iOS Secure Enclave и Desktop OS Keychain/TPM.

### Основные функции
- `generate_anonymous_nickname() -> String`
- `validate_password_strength(password: &str, nickname: &str) -> Result<PasswordPolicyReport, IdentityError>`
- `derive_server_login_id(nickname: &str, server_salt: &[u8; 32]) -> LoginId`
- `start_opaque_registration(password: &str) -> Result<(OpaqueClientRegState, Vec<u8>), IdentityError>`
- `finish_opaque_registration(state: OpaqueClientRegState, server_resp: &[u8], initial_vault: &AccountVaultPayload) -> Result<(Vec<u8>, EncryptedAccountVault, SymmetricKey256), IdentityError>`
- `start_opaque_login(password: &str) -> Result<(OpaqueClientLoginState, Vec<u8>), IdentityError>`
- `finish_opaque_login(state: OpaqueClientLoginState, server_resp: &[u8], encrypted_vault: &EncryptedAccountVault) -> Result<(AccountVaultPayload, SymmetricKey256), IdentityError>`
- `setup_pin_protection(slot: AccountSlotId, pin: &str, duress_pin: Option<&str>, max_attempts: u8, db_key: &SymmetricKey256, keystore: &dyn HardwareKeystoreProvider) -> Result<WrappedKeySlots, IdentityError>`
- `unlock_with_pin(slot: AccountSlotId, pin: &str, wrapped: &mut WrappedKeySlots, keystore: &dyn HardwareKeystoreProvider) -> Result<UnlockOutcome, IdentityError>`
- `check_multiaccount_quota(existing_slots: usize, supporter_pass: Option<&SupporterPassToken>) -> Result<(), IdentityError>`

### Ошибки (`IdentityError`)
- `WeakPassword(PasswordPolicyReport)` — пароль не соответствует требованиям D-0006 (например, меньше 12 символов или меньше 3 заглавных букв).
- `InvalidPinAttemptsRemaining(u8)` — неверный PIN, счётчик попыток уменьшен.
- `PinLockoutWipedRequiresPassword` — исчерпан лимит попыток PIN; обёртка PIN уничтожена в железе, требуется вход по нику и паролю.
- `MultiAccountQuotaExceeded` — попытка создать 4-й профиль без валидного токена `SupporterPass`.
- `InvalidSupporterPass` — слепая подпись токена не прошла проверку.
- `DuressPinCollision` — Duress-PIN совпадает с основным PIN.
- `VaultDecryptionFailed` — повреждён `AccountVault` или неверный ключ экспорта OPAQUE.

## Гарантии
1. **Неизменность стандарта пароля (D-0006):** ни один аккаунт не может быть зарегистрирован со слабым паролем (проверка выполняется внутри Rust-ядра, а не только в UI).
2. **Невидимость ника для сервера:** функция `derive_server_login_id` нормализует ник и пропускает его через `Argon2id` + `BLAKE3` с солью сервера; исходный ник никогда не попадает в сетевые структуры.
3. **Аппаратная защита PIN и неотличимость Duress-PIN:** при исчерпании попыток PIN ключ слота 1 безвозвратно удаляется; при вводе Duress-PIN время ответа и возвращаемый тип неотличимы для наблюдателя от обычного входа.
4. **Честная квота мультиаккаунтов (D-0010):** до 3 профилей создаются без условий, 4+ требуют криптографически валидного `SupporterPassToken`.

## Запрещено вызывающему
- Запрещено кэшировать мастер-пароль или PIN в UI-слое после вызова функций `aegis-identity`.
- Запрещено обходить `validate_password_strength` при регистрации или смене пароля.
- Запрещено передавать один и тот же PIN в качестве основного и `duress_pin`.

## Зависимости
- Внутренние модули: `aegis-crypto`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
