use crate::error::RspassError;

use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit, generic_array::GenericArray},
};
use rand::rngs::OsRng;

pub struct Encryptor {
    pub hash: String,
    pub salt: String,
    cipher: ChaCha20Poly1305,
}

impl Encryptor {
    pub fn new(
        password: &[u8],
        salt: Option<&String>,
    ) -> Result<Self, RspassError> {
        let salt = match salt {
            Some(slt) => SaltString::new(slt.as_str())
                .map_err(|e| RspassError::HashError(e.to_string()))?,
            None => SaltString::generate(&mut OsRng),
        };

        let argon2 = Argon2::default();

        let password_hash = argon2
            .hash_password(password, &salt)
            .map_err(|e| RspassError::HashError(e.to_string()))?
            .to_string();

        let mut key_buf = [0u8; 32];
        argon2
            .hash_password_into(password, &salt.as_bytes(), &mut key_buf)
            .map_err(|e| RspassError::HashError(e.to_string()))?;

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key_buf));

        Ok(Encryptor {
            hash: password_hash,
            salt: salt.as_str().into(),
            cipher: aead,
        })
    }

    pub fn from_hash(hash: String) -> Result<Self, RspassError> {
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&hash)
            .map_err(|e| RspassError::HashError(e.to_string()))?;

        let Some(salt) = parsed_hash.salt else {
            return Err(RspassError::InvalidInputError(
                "Could not get salt from parsed hash".into(),
            ));
        };

        let mut key_buf = [0u8; 32];
        argon2
            .hash_password_into(
                &hash.as_bytes(),
                &salt.as_bytes(),
                &mut key_buf,
            )
            .map_err(|e| RspassError::HashError(e.to_string()))?;

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key_buf));

        Ok(Encryptor {
            hash: hash.clone(),
            salt: salt.to_string(),
            cipher: aead,
        })
    }

    pub fn verify(self: &Self, password: &[u8]) -> bool {
        let parsed_hash = PasswordHash::new(&self.hash).unwrap();

        Argon2::default()
            .verify_password(password, &parsed_hash)
            .is_ok()
    }

    pub fn encrypt(self: &Self, plaintext: &[u8]) -> ([u8; 12], Vec<u8>) {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext =
            self.cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        (*nonce.as_ref(), ciphertext)
    }

    pub fn decrypt(self: &Self, nonce: [u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        self.cipher
            .decrypt(&GenericArray::from(nonce), ciphertext.as_ref())
            .unwrap()
    }

    pub fn decrypt_as_utf8(
        self: &Self,
        nonce: [u8; 12],
        ciphertext: &[u8],
    ) -> String {
        let decrypted = self.decrypt(nonce, ciphertext);
        String::from_utf8(decrypted.clone()).unwrap()
    }
}
