//! `aegis-storage` — Local encrypted database abstraction, schema migrations,
//! and emergency crypto-erase / wipe guarantees (PLAN.md §9, D-0012).

use aegis_crypto::ZeroizingBuffer;
use core::fmt;

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
        if schema_version != SCHEMA_VERSION {
            return Err(StorageError::IncompatibleSchema {
                found: schema_version,
                expected: SCHEMA_VERSION,
            });
        }
        if db_key.len() != DB_KEY_LEN || db_key.iter().all(|&b| b == 0) {
            return Err(StorageError::InvalidKeyMaterial);
        }
        Ok(Self {
            schema_version,
            master_db_key: ZeroizingBuffer::new(db_key),
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
}
