use argon2::{
    Argon2,
    password_hash::{
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, AeadCore, KeyInit},
};
use chacha20poly1305::{Nonce, aead::generic_array::GenericArray};
use rand::rngs::OsRng;

struct Encryptor {
    hash: String,
    cipher: ChaCha20Poly1305,
}

impl Encryptor {
    fn new(password: &[u8]) -> Self {
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

    fn from_hash(hash: String) -> Self {
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

    fn verify(self: &Self, password: &[u8]) -> bool {
        let parsed_hash = PasswordHash::new(&self.hash).unwrap();

        Argon2::default()
            .verify_password(password, &parsed_hash)
            .is_ok()
    }

    fn encrypt(self: &Self, plaintext: &[u8]) -> (Nonce, Vec<u8>) {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let ciphertext =
            self.cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        (nonce, ciphertext)
    }

    fn decrypt(self: &Self, nonce: &Nonce, ciphertext: &[u8]) -> Vec<u8> {
        self.cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap()
    }

    fn decrypt_as_utf8(
        self: &Self,
        nonce: &Nonce,
        ciphertext: &[u8],
    ) -> String {
        let decrypted = self.decrypt(nonce, ciphertext);
        String::from_utf8(decrypted.clone()).unwrap()
    }
}

fn main() {
    // let encryptor = Encryptor::new(b"Epic");

    let encryptor = Encryptor::from_hash(String::from(
        "$argon2id$v=19$m=4096,t=3,p=1$LxPV/tLZi+tja6F2zEsBHw$Kp19ER6J0kN3oSzr06R9QQ202SinlYhPH5XPCS2RXYU",
    ));

    println!("{:?}", encryptor.hash);
    println!("matches: {:?}", encryptor.verify(b"Epic"));

    let plaintext = b"The quick brown fox jumped over the lazy dog.";

    let (nonce, ciphertext) = encryptor.encrypt(plaintext);

    let encoded = general_purpose::STANDARD.encode(&ciphertext);
    println!("Ciphertext: {}", encoded);

    let decrypted = encryptor.decrypt_as_utf8(&nonce, &ciphertext);

    println!("Plaintext: {}", decrypted);
}
