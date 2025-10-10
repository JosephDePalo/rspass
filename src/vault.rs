use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};

use bincode::{Decode, Encode, config};
use serde::{Deserialize, Serialize};

use crate::encryptor::Encryptor;

pub const TEST_PLAINTEXT: &[u8] = b"Vault OK";

#[derive(Debug, Serialize, Deserialize)]
pub struct Vault {
    entries: Vec<Entry>,
}

#[derive(Debug, Serialize, Deserialize)]
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
    ) -> Self {
        let encryptor = Encryptor::new(password.as_bytes(), salt);
        let (test_nonce, test_ciphertext) = encryptor.encrypt(TEST_PLAINTEXT);
        let vault_plaintext = serde_json::to_vec(&vault).unwrap();
        let (vault_nonce, vault_ciphertext) =
            encryptor.encrypt(&vault_plaintext);

        LockedVault {
            test_ciphertext,
            test_nonce,
            vault_ciphertext,
            vault_nonce,
            salt: encryptor.salt.clone(),
        }
    }

    pub fn decrypt(self: &Self, password: &String) -> Vault {
        let encryptor = Encryptor::new(password.as_bytes(), Some(&self.salt));
        let test_decrypted =
            encryptor.decrypt(self.test_nonce, &self.test_ciphertext);
        if test_decrypted != TEST_PLAINTEXT {
            panic!("Bad pass");
        }

        let vault_bytes =
            encryptor.decrypt(self.vault_nonce, &self.vault_ciphertext);

        let vault = serde_json::from_slice(&vault_bytes).unwrap();

        vault
    }
    pub fn encrypt_updated(
        self: &Self,
        password: &String,
        vault: Vault,
    ) -> Self {
        LockedVault::from_vault(vault, password, Some(&self.salt))
    }

    pub fn from_file(file_path: &PathBuf) -> Self {
        let bytes = fs::read(file_path).unwrap();
        let (reading_locked_vault, _): (LockedVault, usize) =
            bincode::decode_from_slice(&bytes, config::standard()).unwrap();
        reading_locked_vault
    }

    pub fn to_file(self: &Self, file_path: &PathBuf) {
        let serialized_locked_vault =
            bincode::encode_to_vec(self, config::standard()).unwrap();

        // Write to file
        let mut writing_file = File::create(file_path).unwrap();
        writing_file.write_all(&serialized_locked_vault).unwrap();
    }
}
