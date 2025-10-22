use std::{
    fmt,
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use bincode::{Decode, Encode, config};
use serde::{Deserialize, Serialize};

use crate::{encryptor::Encryptor, error::RspassError};

pub const TEST_PLAINTEXT: &[u8] = b"Vault OK";

/// Represents a decrypted password vault.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vault {
    /// List of entries.
    entries: Vec<Entry>,
}

/// Represents a single password entry.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    /// Name for the entry.
    name: String,
    /// Username for the account.
    username: String,
    /// Password for the account.
    password: String,
}

impl Vault {
    /// Create a new vault with no entries.
    pub fn new() -> Self {
        Vault { entries: vec![] }
    }

    /// Create a new vault with a vector of entries.
    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Vault { entries }
    }

    /// Add a new entry to the vault.
    pub fn add(self: &mut Self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Get an entry by name from the vault. If there are duplicate entries,
    /// return only the first one.
    pub fn get(self: &Self, name: &str) -> Option<&Entry> {
        for entry in &self.entries {
            if entry.name == name {
                return Some(entry);
            }
        }
        return None;
    }

    /// Removes an entry by name from the vault. If there are duplicate
    /// entries, delete on ly the first one. Returns the removed entry.
    pub fn del(self: &mut Self, name: &str) -> Option<Entry> {
        if let Some(pos) = self.entries.iter().position(|ent| ent.name == name)
        {
            Some(self.entries.remove(pos))
        } else {
            None
        }
    }
}

impl fmt::Display for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined = self
            .entries
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}", joined)
    }
}

impl Entry {
    /// Create a new entry.
    pub fn new(name: String, username: String, password: String) -> Self {
        Entry {
            name,
            username,
            password,
        }
    }
}

impl fmt::Display for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "(Name: {}, Username: {})", self.name, self.username)
    }
}

/// Represents an encrypted vault.
#[derive(Serialize, Deserialize, Encode, Decode)]
pub struct LockedVault {
    /// A block of ciphertext used to test if the right password is being used.
    ///  The plaintext for this block is always "Vault OK".
    test_ciphertext: Vec<u8>,
    /// The nonce used for encrypting `test_ciphertext`.
    test_nonce: [u8; 12],
    /// The encrypted bytes for the underlying vault.
    vault_ciphertext: Vec<u8>,
    /// The nonce used for encrypting `vault_ciphertext`.
    vault_nonce: [u8; 12],
    /// The salt for the password used to encrypt the vault.
    pub salt: String,
}

impl LockedVault {
    /// Creates a `LockedVault` from a `Vault` and password. Optionally takes a
    /// salt and will generate a random one if a salt is not provided.
    pub fn from_vault(
        vault: Vault,
        password: &String,
        salt: Option<&String>,
    ) -> Result<Self, RspassError> {
        let encryptor = Encryptor::new(password.as_bytes(), salt)?;
        let (test_nonce, test_ciphertext) = encryptor.encrypt(TEST_PLAINTEXT);
        let vault_plaintext = serde_json::to_vec(&vault)
            .map_err(|e| RspassError::FormatError(e.to_string()))?;
        let (vault_nonce, vault_ciphertext) =
            encryptor.encrypt(&vault_plaintext);

        Ok(LockedVault {
            test_ciphertext,
            test_nonce,
            vault_ciphertext,
            vault_nonce,
            salt: encryptor.salt.clone(),
        })
    }

    /// Decrypts the enclosed vault and returns it if successful. Otherwise,
    /// returns an error.
    pub fn decrypt(
        self: &Self,
        password: &String,
    ) -> Result<Vault, RspassError> {
        let encryptor = Encryptor::new(password.as_bytes(), Some(&self.salt))?;
        let test_decrypted =
            encryptor.decrypt(self.test_nonce, &self.test_ciphertext);
        if test_decrypted != TEST_PLAINTEXT {
            return Err(RspassError::InvalidInputError(
                "Incorrect password".into(),
            ));
        }

        let vault_bytes =
            encryptor.decrypt(self.vault_nonce, &self.vault_ciphertext);

        let vault = serde_json::from_slice(&vault_bytes)
            .map_err(|e| RspassError::FormatError(e.to_string()))?;

        Ok(vault)
    }

    /// Create a new `LockedVault` from a `Vault` and password.
    pub fn encrypt_updated(
        self: &Self,
        password: &String,
        vault: Vault,
    ) -> Result<Self, RspassError> {
        LockedVault::from_vault(vault, password, Some(&self.salt))
    }

    /// Create a `lockedVault` by reading the file at `file_path`.
    pub fn from_file(file_path: &PathBuf) -> Result<Self, RspassError> {
        let bytes = fs::read(file_path)
            .map_err(|e| RspassError::IOError(e.to_string()))?;
        let (reading_locked_vault, _): (LockedVault, usize) =
            bincode::decode_from_slice(&bytes, config::standard())
                .map_err(|e| RspassError::FormatError(e.to_string()))?;
        Ok(reading_locked_vault)
    }

    /// Serialize and write the `lockedVault` to `file_path`.
    pub fn to_file(
        self: &Self,
        file_path: &PathBuf,
    ) -> Result<(), RspassError> {
        let serialized_locked_vault =
            bincode::encode_to_vec(self, config::standard())
                .map_err(|e| RspassError::FormatError(e.to_string()))?;

        let mut writing_file = File::create(file_path)
            .map_err(|e| RspassError::IOError(e.to_string()))?;
        writing_file
            .write_all(&serialized_locked_vault)
            .map_err(|e| RspassError::IOError(e.to_string()))?;

        Ok(())
    }
}
