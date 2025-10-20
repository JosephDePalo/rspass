use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use bincode::{Decode, Encode, config};
use serde::{Deserialize, Serialize};

use crate::{encryptor::Encryptor, error::RspassError};

pub const TEST_PLAINTEXT: &[u8] = b"Vault OK";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Vault {
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    name: String,
    username: String,
    password: String,
}

impl Vault {
    pub fn new() -> Self {
        Vault { entries: vec![] }
    }

    pub fn from_entries(entries: Vec<Entry>) -> Self {
        Vault { entries }
    }

    pub fn add(self: &mut Self, entry: Entry) {
        self.entries.push(entry);
    }

    pub fn get(self: &Self, name: &str) -> Option<&Entry> {
        for entry in &self.entries {
            if entry.name == name {
                return Some(entry);
            }
        }
        return None;
    }
}

impl Entry {
    pub fn new(name: String, username: String, password: String) -> Self {
        Entry {
            name,
            username,
            password,
        }
    }
}

#[derive(Serialize, Deserialize, Encode, Decode)]
pub struct LockedVault {
    test_ciphertext: Vec<u8>,
    test_nonce: [u8; 12],
    vault_ciphertext: Vec<u8>,
    vault_nonce: [u8; 12],
    pub salt: String,
}

impl LockedVault {
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
    pub fn encrypt_updated(
        self: &Self,
        password: &String,
        vault: Vault,
    ) -> Result<Self, RspassError> {
        LockedVault::from_vault(vault, password, Some(&self.salt))
    }

    pub fn from_file(file_path: &PathBuf) -> Result<Self, RspassError> {
        let bytes = fs::read(file_path)
            .map_err(|e| RspassError::IOError(e.to_string()))?;
        let (reading_locked_vault, _): (LockedVault, usize) =
            bincode::decode_from_slice(&bytes, config::standard())
                .map_err(|e| RspassError::FormatError(e.to_string()))?;
        Ok(reading_locked_vault)
    }

    pub fn to_file(
        self: &Self,
        file_path: &PathBuf,
    ) -> Result<(), RspassError> {
        let serialized_locked_vault =
            bincode::encode_to_vec(self, config::standard())
                .map_err(|e| RspassError::FormatError(e.to_string()))?;

        // Write to file
        let mut writing_file = File::create(file_path)
            .map_err(|e| RspassError::IOError(e.to_string()))?;
        writing_file
            .write_all(&serialized_locked_vault)
            .map_err(|e| RspassError::IOError(e.to_string()))?;

        Ok(())
    }
}
