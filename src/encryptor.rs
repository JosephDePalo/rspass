use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::rngs::OsRng;

pub struct Encryptor {
    pub hash: String,
    cipher: ChaCha20Poly1305,
}

impl Encryptor {
    pub fn new(password: &[u8]) -> Self {
        let salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();

        let password_hash =
            argon2.hash_password(password, &salt).unwrap().to_string();

        let mut key_buf = [0u8; 32];
        argon2
            .hash_password_into(password, &salt.as_bytes(), &mut key_buf)
            .unwrap();

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key_buf));

        Encryptor {
            hash: password_hash,
            cipher: aead,
        }
    }

    pub fn from_hash(hash: String) -> Self {
        let argon2 = Argon2::default();
        let parsed_hash = PasswordHash::new(&hash).unwrap();

        let salt = match parsed_hash.salt {
            Some(s) => s,
            None => panic!("no"),
        };

        let mut key_buf = [0u8; 32];
        argon2
            .hash_password_into(
                &hash.as_bytes(),
                &salt.as_bytes(),
                &mut key_buf,
            )
            .unwrap();

        let aead = ChaCha20Poly1305::new(GenericArray::from_slice(&key_buf));

        Encryptor {
            hash: hash,
            cipher: aead,
        }
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
