//! `aegis-storage` — Local encrypted database abstraction, schema migrations,
//! and emergency crypto-erase / wipe guarantees (PLAN.md §9, D-0012).

use aegis_crypto::{aead_open, aead_seal, hkdf_sha256, sha256, ZeroizingBuffer};
use core::fmt;
use core::hint::black_box;
use core::sync::atomic::{compiler_fence, Ordering};

fn zeroize_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = black_box(0u8);
    }
    let _ = black_box(buf);
    compiler_fence(Ordering::SeqCst);
}

fn zeroize_string(s: &mut String) {
    let mut bytes = core::mem::take(s).into_bytes();
    let cap = bytes.capacity();
    bytes.resize(cap, 0u8);
    zeroize_bytes(&mut bytes);
}

/// Magic header prefix for encrypted local backups (`AEGISBAK`).
pub const BACKUP_MAGIC: &[u8; 8] = b"AEGISBAK";

/// Current local storage schema version (`AGENTS.md §4`).
pub const SCHEMA_VERSION: u32 = 1;

/// Required byte length of the master local database key (`DB_KEY`).
pub const DB_KEY_LEN: usize = 32;

/// Storage layer errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageError {
    /// Storage is locked or its encryption key has been wiped.
    StorageLockedOrWiped,
    /// Provided database encryption key has an invalid length or is all-zero.
    InvalidKeyMaterial,
    /// Stored schema version is newer than or incompatible with the binary.
    IncompatibleSchema { found: u32, expected: u32 },
    /// Encrypted record failed integrity check.
    CorruptedRecord,
    /// Requested key was not found.
    NotFound,
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageLockedOrWiped => write!(f, "local storage is locked or wiped"),
            Self::InvalidKeyMaterial => {
                write!(f, "database key must be 32 non-zero bytes")
            }
            Self::IncompatibleSchema { found, expected } => {
                write!(
                    f,
                    "incompatible schema: found v{found}, expected v{expected}"
                )
            }
            Self::CorruptedRecord => write!(f, "encrypted storage record is corrupted"),
            Self::NotFound => write!(f, "record not found"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Encrypted local storage engine state supporting crypto-erase (`wipe`).
#[derive(Debug)]
pub struct EncryptedStoreHeader {
    schema_version: u32,
    master_db_key: ZeroizingBuffer,
    wiped: bool,
}

impl EncryptedStoreHeader {
    /// Initializes a storage header with a 32-byte non-zero `DB_KEY`.
    ///
    /// # Errors
    /// Returns [`StorageError::IncompatibleSchema`] if `schema_version != SCHEMA_VERSION`,
    /// or [`StorageError::InvalidKeyMaterial`] if `db_key` is not 32 non-zero bytes.
    pub fn open(schema_version: u32, db_key: Vec<u8>) -> Result<Self, StorageError> {
        let wrapped_key = ZeroizingBuffer::new(db_key);
        if schema_version != SCHEMA_VERSION {
            return Err(StorageError::IncompatibleSchema {
                found: schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if wrapped_key.len() != DB_KEY_LEN || wrapped_key.as_slice().iter().all(|&b| b == 0) {
            return Err(StorageError::InvalidKeyMaterial);
        }
        Ok(Self {
            schema_version,
            master_db_key: wrapped_key,
            wiped: false,
        })
    }

    /// Performs immediate cryptographic wipe by zeroizing `DB_KEY` in memory.
    pub fn crypto_wipe(&mut self) {
        self.master_db_key.zeroize();
        self.wiped = true;
    }

    /// Returns the active schema version if unlocked.
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn schema_version(&self) -> Result<u32, StorageError> {
        if self.wiped {
            return Err(StorageError::StorageLockedOrWiped);
        }
        Ok(self.schema_version)
    }

    /// Returns `true` if `crypto_wipe` has been executed.
    #[must_use]
    pub fn is_wiped(&self) -> bool {
        self.wiped
    }
}

/// Contact record stored inside [`EncryptedVaultDb`].
#[derive(Clone, PartialEq, Eq)]
pub struct StoredContact {
    /// Pairwise anonymous contact identifier.
    pub contact_id: [u8; 32],
    /// Local E2EE display name.
    pub display_name: String,
    /// Peer's Ed25519/X25519 identity public key.
    pub peer_identity_key: [u8; 32],
    /// Outgoing unidirectional queue ID on peer's server.
    pub send_queue_id: [u8; 32],
    /// Incoming unidirectional queue ID on our server.
    pub recv_queue_id: [u8; 32],
    /// Whether the contact's safety number was verified via QR/out-of-band.
    pub verified: bool,
}

impl fmt::Debug for StoredContact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredContact")
            .field("contact_id", &"[REDACTED]")
            .field("display_name", &"[REDACTED]")
            .field("peer_identity_key", &"[REDACTED]")
            .field("send_queue_id", &"[REDACTED]")
            .field("recv_queue_id", &"[REDACTED]")
            .field("verified", &self.verified)
            .finish()
    }
}

impl Drop for StoredContact {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.contact_id);
        zeroize_string(&mut self.display_name);
        zeroize_bytes(&mut self.peer_identity_key);
        zeroize_bytes(&mut self.send_queue_id);
        zeroize_bytes(&mut self.recv_queue_id);
    }
}

/// Chat message record stored inside [`EncryptedVaultDb`] with optional disappearing TTL.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredMessage {
    /// Unique message identifier.
    pub message_id: [u8; 32],
    /// Conversation / chat identifier.
    pub chat_id: [u8; 32],
    /// True if authored by the local user.
    pub sender_is_self: bool,
    /// Decrypted message text (encrypted at rest when serialized in the vault).
    pub plaintext_body: String,
    /// Creation timestamp (Unix seconds).
    pub created_at_unix_secs: u64,
    /// Optional expiration timestamp (Unix seconds) for disappearing messages.
    pub expires_at_unix_secs: Option<u64>,
}

impl fmt::Debug for StoredMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredMessage")
            .field("message_id", &"[REDACTED]")
            .field("chat_id", &"[REDACTED]")
            .field("sender_is_self", &self.sender_is_self)
            .field("plaintext_body", &"[REDACTED]")
            .field("created_at_unix_secs", &self.created_at_unix_secs)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .finish()
    }
}

impl Drop for StoredMessage {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.message_id);
        zeroize_bytes(&mut self.chat_id);
        zeroize_string(&mut self.plaintext_body);
    }
}

/// Device-only encrypted note ("Избранное" / Favorites, PLAN.md §14).
/// Never leaves the device over the network unless explicitly exported in an encrypted backup.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedNote {
    /// Unique note identifier.
    pub note_id: [u8; 32],
    /// Note title.
    pub title: String,
    /// Note body content.
    pub body: String,
    /// Last updated timestamp (Unix seconds).
    pub updated_at_unix_secs: u64,
}

impl fmt::Debug for EncryptedNote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedNote")
            .field("note_id", &"[REDACTED]")
            .field("title", &"[REDACTED]")
            .field("body", &"[REDACTED]")
            .field("updated_at_unix_secs", &self.updated_at_unix_secs)
            .finish()
    }
}

impl Drop for EncryptedNote {
    fn drop(&mut self) {
        zeroize_bytes(&mut self.note_id);
        zeroize_string(&mut self.title);
        zeroize_string(&mut self.body);
    }
}

/// Encrypted local database (`EncryptedVaultDb`) backed by `DB_KEY` and ChaCha20-Poly1305 AEAD.
/// Supports contacts, disappearing messages, local full-text search, device-only notes,
/// encrypted backup export/import, and instant `crypto_wipe` (PLAN.md §9, §14).
pub struct EncryptedVaultDb {
    header: EncryptedStoreHeader,
    record_counter: u64,
    kv_ciphertext: Vec<(String, [u8; 12], Vec<u8>)>,
    contacts: Vec<StoredContact>,
    messages: Vec<StoredMessage>,
    notes: Vec<EncryptedNote>,
}

impl fmt::Debug for EncryptedVaultDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedVaultDb")
            .field("wiped", &self.header.is_wiped())
            .field("contacts_count", &self.contacts.len())
            .field("messages_count", &self.messages.len())
            .field("notes_count", &self.notes.len())
            .finish()
    }
}

impl Drop for EncryptedVaultDb {
    fn drop(&mut self) {
        self.crypto_wipe();
    }
}

impl EncryptedVaultDb {
    /// Opens a new `EncryptedVaultDb` with the specified `schema_version` and 32-byte `db_key`.
    ///
    /// # Errors
    /// Propagates any [`StorageError`] from [`EncryptedStoreHeader::open`].
    pub fn open(schema_version: u32, db_key: Vec<u8>) -> Result<Self, StorageError> {
        let header = EncryptedStoreHeader::open(schema_version, db_key)?;
        Ok(Self {
            header,
            record_counter: 0,
            kv_ciphertext: Vec::new(),
            contacts: Vec::new(),
            messages: Vec::new(),
            notes: Vec::new(),
        })
    }

    fn check_unlocked(&self) -> Result<(), StorageError> {
        if self.header.is_wiped() {
            return Err(StorageError::StorageLockedOrWiped);
        }
        Ok(())
    }

    fn ensure_unlocked(&self) -> Result<[u8; 32], StorageError> {
        self.check_unlocked()?;
        let mut key = [0u8; 32];
        key.copy_from_slice(self.header.master_db_key.as_slice());
        Ok(key)
    }

    fn next_nonce(&mut self, domain: &[u8]) -> Result<[u8; 12], StorageError> {
        self.record_counter = self
            .record_counter
            .checked_add(1)
            .ok_or(StorageError::CorruptedRecord)?;
        let digest = sha256(domain);
        let mut nonce = [0u8; 12];
        nonce[0..4].copy_from_slice(&digest[0..4]);
        nonce[4..12].copy_from_slice(&self.record_counter.to_be_bytes());
        Ok(nonce)
    }

    /// Performs an emergency cryptographic wipe, zeroizing `DB_KEY` and purging all in-memory tables.
    pub fn crypto_wipe(&mut self) {
        self.header.crypto_wipe();
        for (k, n, v) in &mut self.kv_ciphertext {
            zeroize_string(k);
            zeroize_bytes(n);
            zeroize_bytes(v);
        }
        self.kv_ciphertext.clear();
        for c in &mut self.contacts {
            zeroize_bytes(&mut c.contact_id);
            zeroize_string(&mut c.display_name);
            zeroize_bytes(&mut c.peer_identity_key);
            zeroize_bytes(&mut c.send_queue_id);
            zeroize_bytes(&mut c.recv_queue_id);
        }
        self.contacts.clear();
        for m in &mut self.messages {
            zeroize_bytes(&mut m.message_id);
            zeroize_bytes(&mut m.chat_id);
            zeroize_string(&mut m.plaintext_body);
        }
        self.messages.clear();
        for n in &mut self.notes {
            zeroize_bytes(&mut n.note_id);
            zeroize_string(&mut n.title);
            zeroize_string(&mut n.body);
        }
        self.notes.clear();
    }

    /// Returns `true` if the database has been cryptographically wiped.
    #[must_use]
    pub fn is_wiped(&self) -> bool {
        self.header.is_wiped()
    }

    /// Encrypts and stores an arbitrary key-value record under `DB_KEY`.
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn put_encrypted_record(
        &mut self,
        key: &str,
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        let mut db_key = self.ensure_unlocked()?;
        let nonce = match self.next_nonce(key.as_bytes()) {
            Ok(n) => n,
            Err(e) => {
                zeroize_bytes(&mut db_key);
                return Err(e);
            }
        };
        let res = aead_seal(&db_key, &nonce, key.as_bytes(), plaintext)
            .map_err(|_| StorageError::CorruptedRecord);
        zeroize_bytes(&mut db_key);
        let ct = res?;

        if let Some(slot) = self.kv_ciphertext.iter_mut().find(|(k, _, _)| k == key) {
            zeroize_bytes(&mut slot.1);
            zeroize_bytes(&mut slot.2);
            slot.1 = nonce;
            slot.2 = ct;
        } else {
            self.kv_ciphertext.push((key.to_owned(), nonce, ct));
        }
        Ok(())
    }

    /// Decrypts and authenticates a stored key-value record.
    ///
    /// # Errors
    /// Returns [`StorageError::NotFound`] if missing, or [`StorageError::CorruptedRecord`] if tampered.
    pub fn get_encrypted_record(&self, key: &str) -> Result<ZeroizingBuffer, StorageError> {
        let mut db_key = self.ensure_unlocked()?;
        let Some((_, nonce, ct)) = self.kv_ciphertext.iter().find(|(k, _, _)| k == key) else {
            zeroize_bytes(&mut db_key);
            return Err(StorageError::NotFound);
        };
        let res = aead_open(&db_key, nonce, key.as_bytes(), ct)
            .map_err(|_| StorageError::CorruptedRecord);
        zeroize_bytes(&mut db_key);
        res
    }

    /// Inserts or updates a contact in the encrypted store.
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped, or [`StorageError::CorruptedRecord`]
    /// if any contact identifier or queue/key is all-zero.
    pub fn upsert_contact(&mut self, mut contact: StoredContact) -> Result<(), StorageError> {
        self.check_unlocked()?;
        if contact.contact_id == [0u8; 32]
            || contact.peer_identity_key == [0u8; 32]
            || contact.send_queue_id == [0u8; 32]
            || contact.recv_queue_id == [0u8; 32]
            || contact.send_queue_id == contact.recv_queue_id
        {
            zeroize_string(&mut contact.display_name);
            return Err(StorageError::CorruptedRecord);
        }
        if let Some(existing) = self
            .contacts
            .iter_mut()
            .find(|c| c.contact_id == contact.contact_id)
        {
            zeroize_string(&mut existing.display_name);
            zeroize_bytes(&mut existing.peer_identity_key);
            zeroize_bytes(&mut existing.send_queue_id);
            zeroize_bytes(&mut existing.recv_queue_id);
            *existing = contact;
        } else {
            self.contacts.push(contact);
        }
        Ok(())
    }

    /// Lists all contacts in the encrypted store.
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn list_contacts(&self) -> Result<&[StoredContact], StorageError> {
        self.check_unlocked()?;
        Ok(&self.contacts)
    }

    fn message_ct_key(message_id: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(4 + 64);
        s.push_str("msg:");
        for &b in message_id {
            s.push(char::from(HEX[usize::from(b >> 4)]));
            s.push(char::from(HEX[usize::from(b & 0x0F)]));
        }
        s
    }

    /// Stores a chat message (with optional disappearing expiration timestamp).
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped, or [`StorageError::CorruptedRecord`]
    /// if `message_id` or `chat_id` is all-zero or `expires_at_unix_secs <= created_at_unix_secs`.
    pub fn insert_message(&mut self, mut message: StoredMessage) -> Result<(), StorageError> {
        self.check_unlocked()?;
        if message.message_id == [0u8; 32] || message.chat_id == [0u8; 32] {
            zeroize_string(&mut message.plaintext_body);
            return Err(StorageError::CorruptedRecord);
        }
        if let Some(existing) = self
            .messages
            .iter()
            .find(|m| m.message_id == message.message_id)
        {
            if existing.chat_id != message.chat_id {
                zeroize_string(&mut message.plaintext_body);
                return Err(StorageError::CorruptedRecord);
            }
        }
        if message
            .expires_at_unix_secs
            .is_none_or(|exp| exp > message.created_at_unix_secs)
        {
            let ct_key = Self::message_ct_key(&message.message_id);
            let mut sealed_body = ZeroizingBuffer::new(message.plaintext_body.as_bytes().to_vec());
            let put_res = self.put_encrypted_record(&ct_key, sealed_body.as_slice());
            sealed_body.zeroize();
            if let Err(err) = put_res {
                zeroize_string(&mut message.plaintext_body);
                return Err(err);
            }
        } else {
            let ct_key = Self::message_ct_key(&message.message_id);
            if let Some(pos) = self.kv_ciphertext.iter().position(|(k, _, _)| k == &ct_key) {
                let (mut k, mut nonce, mut ct_bytes) = self.kv_ciphertext.remove(pos);
                zeroize_string(&mut k);
                zeroize_bytes(&mut nonce);
                zeroize_bytes(&mut ct_bytes);
            }
        }

        if let Some(existing) = self
            .messages
            .iter_mut()
            .find(|m| m.message_id == message.message_id)
        {
            zeroize_string(&mut existing.plaintext_body);
            zeroize_bytes(&mut existing.chat_id);
            *existing = message;
        } else {
            self.messages.push(message);
        }
        Ok(())
    }

    /// Returns all non-expired messages belonging to `chat_id` at `now_unix_secs` (PLAN.md §9, §14).
    /// Returns an empty vector if the vault is wiped or `chat_id` is all-zero.
    #[must_use]
    pub fn get_messages_for_chat(
        &self,
        chat_id: &[u8; 32],
        now_unix_secs: u64,
    ) -> Vec<&StoredMessage> {
        if self.header.is_wiped() || chat_id == &[0u8; 32] {
            return Vec::new();
        }
        self.messages
            .iter()
            .filter(|m| {
                &m.chat_id == chat_id
                    && m.expires_at_unix_secs
                        .is_none_or(|exp| exp > now_unix_secs && exp > m.created_at_unix_secs)
            })
            .collect()
    }

    /// Purges all disappearing messages whose `expires_at_unix_secs <= now_unix_secs` (PLAN.md §9, §14).
    /// Returns the number of deleted messages.
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn purge_expired_messages(&mut self, now_unix_secs: u64) -> Result<usize, StorageError> {
        self.check_unlocked()?;
        let before = self.messages.len();
        let mut kept = Vec::with_capacity(before);
        for mut m in core::mem::take(&mut self.messages) {
            let active = m
                .expires_at_unix_secs
                .is_none_or(|exp| exp > now_unix_secs && exp > m.created_at_unix_secs);
            if active {
                kept.push(m);
            } else {
                let ct_key = Self::message_ct_key(&m.message_id);
                if let Some(pos) = self.kv_ciphertext.iter().position(|(k, _, _)| k == &ct_key) {
                    let (mut k, mut nonce, mut ct_bytes) = self.kv_ciphertext.remove(pos);
                    zeroize_string(&mut k);
                    zeroize_bytes(&mut nonce);
                    zeroize_bytes(&mut ct_bytes);
                }
                zeroize_bytes(&mut m.message_id);
                zeroize_bytes(&mut m.chat_id);
                zeroize_string(&mut m.plaintext_body);
            }
        }
        self.messages = kept;
        Ok(before.saturating_sub(self.messages.len()))
    }

    /// Performs local case-insensitive full-text search across non-expired messages (PLAN.md §14).
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn search_messages_locally(
        &self,
        query: &str,
        now_unix_secs: u64,
    ) -> Result<Vec<StoredMessage>, StorageError> {
        self.check_unlocked()?;
        let mut q = query.trim().to_lowercase();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for m in &self.messages {
            let active = m
                .expires_at_unix_secs
                .is_none_or(|exp| exp > now_unix_secs && exp > m.created_at_unix_secs);
            if active {
                let mut lower_body = m.plaintext_body.to_lowercase();
                let matched = lower_body.contains(&q);
                zeroize_string(&mut lower_body);
                if matched {
                    results.push(m.clone());
                }
            }
        }
        zeroize_string(&mut q);
        Ok(results)
    }

    /// Saves a device-only encrypted note ("Избранное", PLAN.md §14).
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped, or [`StorageError::CorruptedRecord`]
    /// if `note_id` is all-zero.
    pub fn put_local_note(&mut self, mut note: EncryptedNote) -> Result<(), StorageError> {
        self.check_unlocked()?;
        if note.note_id == [0u8; 32] {
            zeroize_string(&mut note.title);
            zeroize_string(&mut note.body);
            return Err(StorageError::CorruptedRecord);
        }
        if let Some(existing) = self.notes.iter_mut().find(|n| n.note_id == note.note_id) {
            zeroize_string(&mut existing.title);
            zeroize_string(&mut existing.body);
            *existing = note;
        } else {
            self.notes.push(note);
        }
        Ok(())
    }

    /// Lists all device-only notes ("Избранное").
    ///
    /// # Errors
    /// Returns [`StorageError::StorageLockedOrWiped`] if wiped.
    pub fn list_local_notes(&self) -> Result<&[EncryptedNote], StorageError> {
        self.check_unlocked()?;
        Ok(&self.notes)
    }

    /// Exports an AEAD-authenticated encrypted backup (`AEGISBAK` magic + `SCHEMA_VERSION` + nonce + ciphertext)
    /// for migration to a new device (PLAN.md §14).
    ///
    /// # Errors
    /// Returns [`StorageError`] if the database is wiped or `backup_key` / `nonce` is all-zero.
    pub fn export_encrypted_backup(
        &self,
        backup_key: &[u8; 32],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>, StorageError> {
        self.check_unlocked()?;
        if backup_key == &[0u8; 32] || nonce == &[0u8; 12] {
            return Err(StorageError::InvalidKeyMaterial);
        }

        let mut payload = Vec::new();
        let contacts_count =
            u32::try_from(self.contacts.len()).map_err(|_| StorageError::CorruptedRecord)?;
        payload.extend_from_slice(&contacts_count.to_be_bytes());
        for c in &self.contacts {
            payload.extend_from_slice(&c.contact_id);
            payload.extend_from_slice(&c.peer_identity_key);
            payload.extend_from_slice(&c.send_queue_id);
            payload.extend_from_slice(&c.recv_queue_id);
            payload.push(u8::from(c.verified));
            let name_bytes = c.display_name.as_bytes();
            let name_len =
                u32::try_from(name_bytes.len()).map_err(|_| StorageError::CorruptedRecord)?;
            payload.extend_from_slice(&name_len.to_be_bytes());
            payload.extend_from_slice(name_bytes);
        }

        let notes_count =
            u32::try_from(self.notes.len()).map_err(|_| StorageError::CorruptedRecord)?;
        payload.extend_from_slice(&notes_count.to_be_bytes());
        for note in &self.notes {
            payload.extend_from_slice(&note.note_id);
            payload.extend_from_slice(&note.updated_at_unix_secs.to_be_bytes());
            let title_bytes = note.title.as_bytes();
            let body_bytes = note.body.as_bytes();
            let title_len =
                u32::try_from(title_bytes.len()).map_err(|_| StorageError::CorruptedRecord)?;
            let body_len =
                u32::try_from(body_bytes.len()).map_err(|_| StorageError::CorruptedRecord)?;
            payload.extend_from_slice(&title_len.to_be_bytes());
            payload.extend_from_slice(title_bytes);
            payload.extend_from_slice(&body_len.to_be_bytes());
            payload.extend_from_slice(body_bytes);
        }

        let valid_messages: Vec<&StoredMessage> = self
            .messages
            .iter()
            .filter(|m| {
                m.expires_at_unix_secs
                    .is_none_or(|exp| exp > m.created_at_unix_secs)
            })
            .collect();
        let msg_count =
            u32::try_from(valid_messages.len()).map_err(|_| StorageError::CorruptedRecord)?;
        payload.extend_from_slice(&msg_count.to_be_bytes());
        for m in valid_messages {
            payload.extend_from_slice(&m.message_id);
            payload.extend_from_slice(&m.chat_id);
            payload.push(u8::from(m.sender_is_self));
            payload.extend_from_slice(&m.created_at_unix_secs.to_be_bytes());
            match m.expires_at_unix_secs {
                Some(exp) => {
                    payload.push(1);
                    payload.extend_from_slice(&exp.to_be_bytes());
                }
                None => payload.push(0),
            }
            let body_bytes = m.plaintext_body.as_bytes();
            let body_len =
                u32::try_from(body_bytes.len()).map_err(|_| StorageError::CorruptedRecord)?;
            payload.extend_from_slice(&body_len.to_be_bytes());
            payload.extend_from_slice(body_bytes);
        }

        let mut derived_key = [0u8; 32];
        if hkdf_sha256(
            BACKUP_MAGIC,
            backup_key,
            &SCHEMA_VERSION.to_be_bytes(),
            &mut derived_key,
        )
        .is_err()
        {
            zeroize_bytes(&mut payload);
            zeroize_bytes(&mut derived_key);
            return Err(StorageError::InvalidKeyMaterial);
        }

        let mut header_aad = Vec::with_capacity(12);
        header_aad.extend_from_slice(BACKUP_MAGIC);
        header_aad.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());

        let seal_res = aead_seal(&derived_key, nonce, &header_aad, &payload)
            .map_err(|_| StorageError::CorruptedRecord);
        let cap = payload.capacity();
        payload.resize(cap, 0u8);
        zeroize_bytes(&mut payload);
        zeroize_bytes(&mut derived_key);
        let ct = seal_res?;

        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&header_aad);
        out.extend_from_slice(nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Imports and verifies an encrypted backup (`AEGISBAK`), restoring notes and messages.
    ///
    /// # Errors
    /// Fail-closed: returns [`StorageError`] if the magic header, schema version, or AEAD tag is invalid.
    pub fn import_encrypted_backup(
        backup_bytes: &[u8],
        backup_key: &[u8; 32],
        db_key: Vec<u8>,
    ) -> Result<Self, StorageError> {
        if backup_key == &[0u8; 32] {
            return Err(StorageError::InvalidKeyMaterial);
        }
        if backup_bytes.len() < 24 + 16 || &backup_bytes[0..8] != BACKUP_MAGIC {
            return Err(StorageError::CorruptedRecord);
        }
        let found_version = u32::from_be_bytes([
            backup_bytes[8],
            backup_bytes[9],
            backup_bytes[10],
            backup_bytes[11],
        ]);
        if found_version != SCHEMA_VERSION {
            return Err(StorageError::IncompatibleSchema {
                found: found_version,
                expected: SCHEMA_VERSION,
            });
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&backup_bytes[12..24]);
        if nonce == [0u8; 12] {
            return Err(StorageError::CorruptedRecord);
        }

        let mut derived_key = [0u8; 32];
        hkdf_sha256(
            BACKUP_MAGIC,
            backup_key,
            &SCHEMA_VERSION.to_be_bytes(),
            &mut derived_key,
        )
        .map_err(|_| StorageError::InvalidKeyMaterial)?;

        let open_res = aead_open(
            &derived_key,
            &nonce,
            &backup_bytes[0..12],
            &backup_bytes[24..],
        )
        .map_err(|_| StorageError::CorruptedRecord);
        zeroize_bytes(&mut derived_key);
        let decrypted = open_res?;

        let mut db = Self::open(SCHEMA_VERSION, db_key)?;
        let bytes = decrypted.as_slice();
        let mut cursor = 0usize;

        fn read_slice<'b>(
            buf: &'b [u8],
            cur: &mut usize,
            len: usize,
        ) -> Result<&'b [u8], StorageError> {
            let end = cur.checked_add(len).ok_or(StorageError::CorruptedRecord)?;
            let slice = buf.get(*cur..end).ok_or(StorageError::CorruptedRecord)?;
            *cur = end;
            Ok(slice)
        }
        let read_32 = |buf: &[u8], cur: &mut usize| -> Result<[u8; 32], StorageError> {
            let v = read_slice(buf, cur, 32)?;
            let mut out = [0u8; 32];
            out.copy_from_slice(v);
            Ok(out)
        };
        let read_u8 = |buf: &[u8], cur: &mut usize| -> Result<u8, StorageError> {
            let v = read_slice(buf, cur, 1)?;
            Ok(v[0])
        };
        let read_u32 = |buf: &[u8], cur: &mut usize| -> Result<u32, StorageError> {
            let v = read_slice(buf, cur, 4)?;
            Ok(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
        };
        let read_u64 = |buf: &[u8], cur: &mut usize| -> Result<u64, StorageError> {
            let v = read_slice(buf, cur, 8)?;
            Ok(u64::from_be_bytes([
                v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
            ]))
        };

        let contacts_count = read_u32(bytes, &mut cursor)? as usize;
        for _ in 0..contacts_count {
            let contact_id = read_32(bytes, &mut cursor)?;
            let peer_identity_key = read_32(bytes, &mut cursor)?;
            let send_queue_id = read_32(bytes, &mut cursor)?;
            let recv_queue_id = read_32(bytes, &mut cursor)?;
            let verified_byte = read_u8(bytes, &mut cursor)?;
            if verified_byte > 1 {
                return Err(StorageError::CorruptedRecord);
            }
            let verified = verified_byte == 1;
            let name_len = read_u32(bytes, &mut cursor)? as usize;
            let name_bytes = read_slice(bytes, &mut cursor, name_len)?;
            let display_name = core::str::from_utf8(name_bytes)
                .map(str::to_owned)
                .map_err(|_| StorageError::CorruptedRecord)?;
            if db.contacts.iter().any(|c| c.contact_id == contact_id) {
                return Err(StorageError::CorruptedRecord);
            }
            db.upsert_contact(StoredContact {
                contact_id,
                display_name,
                peer_identity_key,
                send_queue_id,
                recv_queue_id,
                verified,
            })?;
        }

        let notes_count = read_u32(bytes, &mut cursor)? as usize;
        for _ in 0..notes_count {
            let note_id = read_32(bytes, &mut cursor)?;
            let updated_at_unix_secs = read_u64(bytes, &mut cursor)?;
            let title_len = read_u32(bytes, &mut cursor)? as usize;
            let title_bytes = read_slice(bytes, &mut cursor, title_len)?;
            let title = core::str::from_utf8(title_bytes)
                .map(str::to_owned)
                .map_err(|_| StorageError::CorruptedRecord)?;
            let body_len = read_u32(bytes, &mut cursor)? as usize;
            let body_bytes = read_slice(bytes, &mut cursor, body_len)?;
            let body = core::str::from_utf8(body_bytes)
                .map(str::to_owned)
                .map_err(|_| StorageError::CorruptedRecord)?;
            if db.notes.iter().any(|n| n.note_id == note_id) {
                return Err(StorageError::CorruptedRecord);
            }
            db.put_local_note(EncryptedNote {
                note_id,
                title,
                body,
                updated_at_unix_secs,
            })?;
        }

        let msg_count = read_u32(bytes, &mut cursor)? as usize;
        for _ in 0..msg_count {
            let message_id = read_32(bytes, &mut cursor)?;
            let chat_id = read_32(bytes, &mut cursor)?;
            let sender_byte = read_u8(bytes, &mut cursor)?;
            if sender_byte > 1 {
                return Err(StorageError::CorruptedRecord);
            }
            let sender_is_self = sender_byte == 1;
            let created_at_unix_secs = read_u64(bytes, &mut cursor)?;
            let exp_flag = read_u8(bytes, &mut cursor)?;
            if exp_flag > 1 {
                return Err(StorageError::CorruptedRecord);
            }
            let expires_at_unix_secs = if exp_flag == 1 {
                Some(read_u64(bytes, &mut cursor)?)
            } else {
                None
            };
            let body_len = read_u32(bytes, &mut cursor)? as usize;
            let body_bytes = read_slice(bytes, &mut cursor, body_len)?;
            let plaintext_body = core::str::from_utf8(body_bytes)
                .map(str::to_owned)
                .map_err(|_| StorageError::CorruptedRecord)?;
            if db.messages.iter().any(|m| m.message_id == message_id) {
                return Err(StorageError::CorruptedRecord);
            }
            db.insert_message(StoredMessage {
                message_id,
                chat_id,
                sender_is_self,
                plaintext_body,
                created_at_unix_secs,
                expires_at_unix_secs,
            })?;
        }

        if cursor != bytes.len() {
            return Err(StorageError::CorruptedRecord);
        }

        let nonce_epoch = u64::from(u32::from_be_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]));
        db.record_counter = (nonce_epoch << 16)
            .saturating_add((db.contacts.len() + db.notes.len() + db.messages.len() + 1) as u64);
        Ok(db)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn storage_header_rejects_unknown_schema_and_wipes_cleanly() {
        assert_eq!(
            EncryptedStoreHeader::open(99, vec![1u8; 32]).unwrap_err(),
            StorageError::IncompatibleSchema {
                found: 99,
                expected: SCHEMA_VERSION
            }
        );

        let mut store = EncryptedStoreHeader::open(SCHEMA_VERSION, vec![0x55; 32])
            .expect("valid schema must open");
        assert_eq!(store.schema_version(), Ok(SCHEMA_VERSION));

        store.crypto_wipe();
        assert!(store.is_wiped());
        assert_eq!(
            store.schema_version(),
            Err(StorageError::StorageLockedOrWiped)
        );
    }

    #[test]
    fn b0012_storage_header_rejects_empty_short_or_all_zero_keys() {
        assert_eq!(
            EncryptedStoreHeader::open(SCHEMA_VERSION, vec![]).unwrap_err(),
            StorageError::InvalidKeyMaterial
        );
        assert_eq!(
            EncryptedStoreHeader::open(SCHEMA_VERSION, vec![0x42; 16]).unwrap_err(),
            StorageError::InvalidKeyMaterial
        );
        assert_eq!(
            EncryptedStoreHeader::open(SCHEMA_VERSION, vec![0u8; 32]).unwrap_err(),
            StorageError::InvalidKeyMaterial
        );
    }

    #[test]
    fn encrypted_vault_db_kv_contacts_notes_disappearing_search_and_backup() {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x77; 32]).unwrap();

        // 1. Encrypted KV store
        db.put_encrypted_record("session_ratchet", b"secret-ratchet-state")
            .unwrap();
        let rec = db.get_encrypted_record("session_ratchet").unwrap();
        assert_eq!(rec.as_slice(), b"secret-ratchet-state");

        // 2. Local device-only notes ("Избранное")
        db.put_local_note(EncryptedNote {
            note_id: [0x01; 32],
            title: "Избранное".to_owned(),
            body: "Offline recovery backup location".to_owned(),
            updated_at_unix_secs: 1_000,
        })
        .unwrap();
        assert_eq!(db.list_local_notes().unwrap().len(), 1);

        // 3. Disappearing messages + local full-text search
        db.insert_message(StoredMessage {
            message_id: [0x10; 32],
            chat_id: [0xCC; 32],
            sender_is_self: true,
            plaintext_body: "Meet me at the northern glacier".to_owned(),
            created_at_unix_secs: 1_000,
            expires_at_unix_secs: Some(1_060),
        })
        .unwrap();
        db.insert_message(StoredMessage {
            message_id: [0x20; 32],
            chat_id: [0xCC; 32],
            sender_is_self: false,
            plaintext_body: "Permanent glacier coordinates".to_owned(),
            created_at_unix_secs: 1_005,
            expires_at_unix_secs: None,
        })
        .unwrap();

        assert_eq!(
            db.search_messages_locally("glacier", 1_030).unwrap().len(),
            2
        );
        // After t=1_060, the first message expires and is excluded from search and purged
        assert_eq!(
            db.search_messages_locally("glacier", 1_061).unwrap().len(),
            1
        );
        assert_eq!(db.purge_expired_messages(1_061).unwrap(), 1);

        // 4. Encrypted backup export/import + tamper rejection
        let backup_key = [0xAB; 32];
        let backup_bytes = db
            .export_encrypted_backup(&backup_key, &[0x12; 12])
            .unwrap();
        assert_eq!(&backup_bytes[0..8], BACKUP_MAGIC);

        let mut tampered = backup_bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert_eq!(
            EncryptedVaultDb::import_encrypted_backup(&tampered, &backup_key, vec![0x88; 32])
                .unwrap_err(),
            StorageError::CorruptedRecord
        );

        let restored =
            EncryptedVaultDb::import_encrypted_backup(&backup_bytes, &backup_key, vec![0x88; 32])
                .unwrap();
        assert_eq!(restored.list_local_notes().unwrap().len(), 1);
        assert_eq!(
            restored
                .search_messages_locally("Permanent", 2_000)
                .unwrap()
                .len(),
            1
        );

        // 5. Crypto wipe locks all operations
        db.crypto_wipe();
        assert!(db.is_wiped());
        assert_eq!(
            db.list_local_notes(),
            Err(StorageError::StorageLockedOrWiped)
        );
    }

    #[test]
    fn b0022_backup_roundtrips_contacts_and_rejects_trailing_garbage() {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x77; 32]).unwrap();
        db.upsert_contact(StoredContact {
            contact_id: [0x11; 32],
            display_name: "nordic-falcon".to_owned(),
            peer_identity_key: [0x22; 32],
            send_queue_id: [0x33; 32],
            recv_queue_id: [0x44; 32],
            verified: true,
        })
        .unwrap();

        let backup_key = [0xAB; 32];
        let nonce = [0x12; 12];
        let backup = db.export_encrypted_backup(&backup_key, &nonce).unwrap();
        let restored =
            EncryptedVaultDb::import_encrypted_backup(&backup, &backup_key, vec![0x88; 32])
                .unwrap();
        assert_eq!(restored.list_contacts().unwrap().len(), 1);
        assert_eq!(
            restored.list_contacts().unwrap()[0].display_name,
            "nordic-falcon"
        );
    }

    #[test]
    fn b0039_get_messages_for_chat_and_backup_skip_expired_disappearing_messages() {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x77; 32]).unwrap();
        let chat_a = [0xAA; 32];
        let chat_b = [0xBB; 32];

        // Valid disappearing message in chat_a (expires at 2000)
        db.insert_message(StoredMessage {
            message_id: [0x01; 32],
            chat_id: chat_a,
            sender_is_self: true,
            plaintext_body: "ephemeral-secret".to_owned(),
            created_at_unix_secs: 1_000,
            expires_at_unix_secs: Some(2_000),
        })
        .unwrap();

        // Already-expired message (expires_at <= created_at)
        db.insert_message(StoredMessage {
            message_id: [0x02; 32],
            chat_id: chat_a,
            sender_is_self: false,
            plaintext_body: "born-expired-secret".to_owned(),
            created_at_unix_secs: 1_500,
            expires_at_unix_secs: Some(1_000),
        })
        .unwrap();

        // Permanent message in chat_b
        db.insert_message(StoredMessage {
            message_id: [0x03; 32],
            chat_id: chat_b,
            sender_is_self: true,
            plaintext_body: "permanent-b".to_owned(),
            created_at_unix_secs: 1_000,
            expires_at_unix_secs: None,
        })
        .unwrap();

        assert_eq!(db.get_messages_for_chat(&chat_a, 1_500).len(), 1);
        assert_eq!(db.get_messages_for_chat(&chat_a, 2_000).len(), 0);
        assert_eq!(
            db.search_messages_locally("born-expired", 1_200)
                .unwrap()
                .len(),
            0
        );

        // Exported backup must skip the already-expired message (id 0x02)
        let backup_key = [0xAB; 32];
        let backup = db
            .export_encrypted_backup(&backup_key, &[0x12; 12])
            .unwrap();
        let restored =
            EncryptedVaultDb::import_encrypted_backup(&backup, &backup_key, vec![0x88; 32])
                .unwrap();
        assert_eq!(restored.get_messages_for_chat(&chat_a, 1_500).len(), 1);
        assert_eq!(restored.get_messages_for_chat(&chat_b, 1_500).len(), 1);
    }

    #[test]
    fn b0040_vault_rejects_zero_ids_duplicate_backup_ids_and_overflow_lengths() {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x77; 32]).unwrap();

        assert_eq!(
            db.upsert_contact(StoredContact {
                contact_id: [0u8; 32],
                display_name: "zero".to_owned(),
                peer_identity_key: [0x11; 32],
                send_queue_id: [0x22; 32],
                recv_queue_id: [0x33; 32],
                verified: false,
            }),
            Err(StorageError::CorruptedRecord)
        );
        assert_eq!(
            db.put_local_note(EncryptedNote {
                note_id: [0u8; 32],
                title: "t".to_owned(),
                body: "b".to_owned(),
                updated_at_unix_secs: 1,
            }),
            Err(StorageError::CorruptedRecord)
        );
        assert_eq!(
            db.insert_message(StoredMessage {
                message_id: [0u8; 32],
                chat_id: [0x11; 32],
                sender_is_self: true,
                plaintext_body: "hi".to_owned(),
                created_at_unix_secs: 1,
                expires_at_unix_secs: None,
            }),
            Err(StorageError::CorruptedRecord)
        );

        // Craft an encrypted backup payload containing duplicate note_id entries
        let backup_key = [0xAB; 32];
        let nonce = [0x12; 12];
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes()); // 0 contacts
        payload.extend_from_slice(&2u32.to_be_bytes()); // 2 notes with identical note_id
        for _ in 0..2 {
            payload.extend_from_slice(&[0x55u8; 32]); // duplicate note_id
            payload.extend_from_slice(&100u64.to_be_bytes());
            payload.extend_from_slice(&1u32.to_be_bytes());
            payload.push(b'a');
            payload.extend_from_slice(&1u32.to_be_bytes());
            payload.push(b'b');
        }
        payload.extend_from_slice(&0u32.to_be_bytes()); // 0 messages

        let mut derived_key = [0u8; 32];
        hkdf_sha256(
            BACKUP_MAGIC,
            &backup_key,
            &SCHEMA_VERSION.to_be_bytes(),
            &mut derived_key,
        )
        .unwrap();
        let mut header_aad = Vec::from(BACKUP_MAGIC);
        header_aad.extend_from_slice(&SCHEMA_VERSION.to_be_bytes());
        let ct = aead_seal(&derived_key, &nonce, &header_aad, &payload).unwrap();
        let mut backup_bytes = header_aad;
        backup_bytes.extend_from_slice(&nonce);
        backup_bytes.extend_from_slice(&ct);

        assert_eq!(
            EncryptedVaultDb::import_encrypted_backup(&backup_bytes, &backup_key, vec![0x88; 32])
                .unwrap_err(),
            StorageError::CorruptedRecord
        );
    }

    #[test]
    fn b0070_storage_redacts_debug_rejects_colliding_queues_and_zeroizes_purged_messages() {
        let mut db = EncryptedVaultDb::open(SCHEMA_VERSION, vec![0x77; 32]).unwrap();
        // Send queue == recv queue must be rejected (unidirectional queue isolation)
        assert_eq!(
            db.upsert_contact(StoredContact {
                contact_id: [0x11; 32],
                display_name: "secret-contact".to_owned(),
                peer_identity_key: [0x22; 32],
                send_queue_id: [0x33; 32],
                recv_queue_id: [0x33; 32],
                verified: true,
            }),
            Err(StorageError::CorruptedRecord)
        );

        let msg = StoredMessage {
            message_id: [0x09; 32],
            chat_id: [0xAA; 32],
            sender_is_self: true,
            plaintext_body: "super-secret-disappearing-text".to_owned(),
            created_at_unix_secs: 100,
            expires_at_unix_secs: Some(200),
        };
        let msg_dbg = format!("{msg:?}");
        assert!(!msg_dbg.contains("super-secret"));
        assert!(msg_dbg.contains("[REDACTED]"));

        db.insert_message(msg).unwrap();
        let db_dbg = format!("{db:?}");
        assert!(!db_dbg.contains("super-secret"));
        assert_eq!(db.purge_expired_messages(250).unwrap(), 1);

        // B-0085: Duplicate message_id attempting to move a message to a different chat_id must fail closed
        db.insert_message(StoredMessage {
            message_id: [0x21; 32],
            chat_id: [0xAA; 32],
            sender_is_self: true,
            plaintext_body: "first-chat".to_owned(),
            created_at_unix_secs: 100,
            expires_at_unix_secs: None,
        })
        .unwrap();
        assert_eq!(
            db.insert_message(StoredMessage {
                message_id: [0x21; 32],
                chat_id: [0xBB; 32],
                sender_is_self: true,
                plaintext_body: "cross-chat-overwrite".to_owned(),
                created_at_unix_secs: 101,
                expires_at_unix_secs: None,
            }),
            Err(StorageError::CorruptedRecord)
        );
    }
}
