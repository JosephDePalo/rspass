use cryptostuff::encryptor::*;
use cryptostuff::vault::{Entry, Vault};

use serde_json;
use std::fs::File;
use std::io::Write;

fn main() {
    let encryptor = Encryptor::from_hash(String::from(
        "$argon2id$v=19$m=4096,t=3,p=1$LxPV/tLZi+tja6F2zEsBHw$Kp19ER6J0kN3oSzr06R9QQ202SinlYhPH5XPCS2RXYU",
    ));

    let entries = vec![
        Entry::new("github".into(), "epic".into(), "password123".into()),
        Entry::new("fiveguys".into(), "awesomeguy".into(), "qwertyqwop".into()),
    ];

    let vault = Vault::from_entries(entries);

    let plaintext = serde_json::to_string_pretty(&vault).unwrap();
    println!("{plaintext:?}");

    let (nonce, ciphertext) = encryptor.encrypt(plaintext.as_bytes());

    // Write to file
    let mut file = File::create("vault_enc").unwrap();
    file.write_all(&ciphertext).unwrap();

    let decrypted = encryptor.decrypt_as_utf8(&nonce, &ciphertext);

    println!("Plaintext: {}", decrypted);
}
