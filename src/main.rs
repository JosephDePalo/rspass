use base64::{Engine as _, engine::general_purpose};
use cryptostuff::encryptor::*;

fn main() {
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
