use argon2::password_hash::SaltString;
use bincode::{Decode, Encode};
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
    pub fn from_vault(encryptor: &Encryptor, vault: Vault) -> Self {
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

    // TODO: Change to Result from Option
    pub fn unlock_vault(self: &Self, encryptor: &Encryptor) -> Option<Vault> {
        let test_decrypted =
            encryptor.decrypt(self.test_nonce, &self.test_ciphertext);
        if test_decrypted != TEST_PLAINTEXT {
            return None;
        }

        let vault_bytes =
            encryptor.decrypt(self.vault_nonce, &self.vault_ciphertext);

        let vault = serde_json::from_slice(&vault_bytes).unwrap();

        return Some(vault);
    }

    pub fn decrypt(self: &Self, password: &String) -> Vault {
        let encryptor = Encryptor::new(password.as_bytes(), Some(&self.salt));
        let unlocked_vault = match self.unlock_vault(&encryptor) {
            Some(vault) => vault,
            None => panic!("Couldn't unlock vault"),
        };
        unlocked_vault
    }
    pub fn encrypt_updated(
        self: &Self,
        password: &String,
        vault: Vault,
    ) -> Self {
        let encryptor = Encryptor::new(password.as_bytes(), Some(&self.salt));
        let locked_vault = LockedVault::from_vault(&encryptor, vault);
        locked_vault
    }
}
