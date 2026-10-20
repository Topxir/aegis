# Контракт: aegis-storage
Версия контракта: 0.1

## Ответственность
Обеспечивает надёжное, зашифрованное локальное хранение данных на устройстве пользователя (PLAN.md §9, AGENTS.md §2):
- Управление изолированными базами данных **SQLCipher** для каждого слота мультиаккаунта (`AccountSlotId`) и отдельной базой-обманкой для режима `Duress-PIN`;
- Хранение сообщений, контактов, состояний сессий `Double Ratchet` / `MLS`, параметров односторонних очередей и локального поискового индекса внутри зашифрованной БД;
- Индивидуальное потоковое шифрование файлов вложений на диске (`XChaCha20-Poly1305`, уникальный ключ `FileKey` на каждый файл, хранящийся только внутри SQLCipher БД);
- Автоматическое удаление исчезающих сообщений по таймеру (`TTL`) с перезаписью страниц БД (`PRAGMA secure_delete = ON`);
- Мгновенное криптографическое стирание (`crypto_wipe`) отдельного слота, отдельной скомпрометированной очереди или всех данных устройства по тревоге / Duress-PIN;
- Версионируемые миграции схемы БД (`schema_version`).

## Публичное API (функции, типы, ошибки)

### Типы
- `StorageConfig { base_dir: PathBuf, slot_id: AccountSlotId, page_size: u32 }`
- `EncryptedStorage` — дескриптор открытого зашифрованного хранилища слота.
- `StoredContact`, `StoredConversation`, `StoredMessage`, `StoredQueueBinding`, `StoredAttachmentMeta`.
- `SchemaVersion(u32)` — текущая версия схемы локальной БД.

### Основные функции
- `open_storage(config: &StorageConfig, db_key: &SymmetricKey256) -> Result<EncryptedStorage, StorageError>`
- `lock_and_zeroize(storage: EncryptedStorage) -> Result<(), StorageError>`
- `wipe_slot_cryptographic(base_dir: &Path, slot_id: AccountSlotId) -> Result<(), StorageError>`
- `wipe_all_slots_emergency(base_dir: &Path) -> Result<(), StorageError>`
- `save_ratchet_session(storage: &EncryptedStorage, contact_id: &[u8; 32], state_ciphertext: &[u8]) -> Result<(), StorageError>`
- `bind_unidirectional_queue(storage: &EncryptedStorage, contact_id: &[u8; 32], queue: &StoredQueueBinding) -> Result<(), StorageError>`
- `delete_compromised_queue(storage: &EncryptedStorage, queue_id: &[u8; 32]) -> Result<(), StorageError>`
- `store_encrypted_attachment(storage: &EncryptedStorage, plaintext_stream: &mut dyn Read) -> Result<StoredAttachmentMeta, StorageError>`
- `read_encrypted_attachment(storage: &EncryptedStorage, meta: &StoredAttachmentMeta) -> Result<Zeroizing<Vec<u8>>, StorageError>`
- `purge_expired_messages(storage: &EncryptedStorage, now_unix: u64) -> Result<usize, StorageError>`

### Ошибки (`StorageError`)
- `DatabaseLockedOrInvalidKey` — неверный `DB_KEY` или повреждён заголовок SQLCipher.
- `MigrationFailed { from: u32, to: u32 }` — ошибка миграции схемы с автоматическим откатом транзакции.
- `AttachmentIntegrityError` — ошибка проверки тега Poly1305 при чтении зашифрованного файла вложения.
- `SlotNotFound` / `IoError` — ошибка ввода-вывода файловой системы.
- `QuotaExceeded` — превышен локальный лимит размера вложений или слотов.

## Гарантии
1. **Никаких открытых данных на диске:** ни один байт текста сообщения, имени контакта, состояния рэтчета или вложения не записывается на диск вне SQLCipher или `XChaCha20-Poly1305`.
2. **Защита памяти SQLCipher:** при открытии соединения принудительно выставляются `PRAGMA cipher_page_size = 4096; PRAGMA cipher_memory_security = ON; PRAGMA secure_delete = ON; PRAGMA foreign_keys = ON;`.
3. **Изоляция мультиаккаунтов:** каждый `AccountSlotId` использует физически отдельный файл БД с независимым `DB_KEY`.
4. **Атомарность миграций:** каждая миграция `schema_version` выполняется внутри эксклюзивной транзакции; при ошибке база остаётся в консистентном состоянии предыдущей версии.

## Запрещено вызывающему
- Запрещено передавать пути `base_dir`, попадающие в системные облачные бэкапы (Google Drive Backup, iCloud Backup, OneDrive).
- Запрещено хранить сырые SQL-запросы или работать с `rusqlite` напрямую в обход `aegis-storage`.
- Запрещено сохранять временные расшифрованные файлы вложений в публичные директории ОС (`/tmp`, `Downloads`, внешнюю SD-карту) без явного действия экспорта пользователем.

## Зависимости
- Внутренние модули: `aegis-crypto`, `aegis-identity`.
- Внешние крейты: `rusqlite` (`bundled-sqlcipher-vendored-openssl`), `zeroize`.

## История изменений
- `0.1` (2026-10-20, T-0002): Первичная спецификация контракта.
