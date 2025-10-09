use cryptostuff::encryptor::*;
use cryptostuff::vault::{Entry, LockedVault, Vault};

use bincode::{self, config};
use std::fs::{self, File};
use std::io::Write;

fn main() {
    let encryptor = Encryptor::new(b"Epic");

    let entries = vec![
        Entry::new("github".into(), "epic".into(), "password123".into()),
        Entry::new("fiveguys".into(), "awesomeguy".into(), "qwertyqwop".into()),
    ];
    let vault = Vault::from_entries(entries);

    let writing_locked_vault = LockedVault::from_vault(&encryptor, vault);

    let serialized_locked_vault =
        bincode::encode_to_vec(&writing_locked_vault, config::standard())
            .unwrap();

    // Write to file
    let mut writing_file = File::create("vault_enc").unwrap();
    writing_file.write_all(&serialized_locked_vault).unwrap();

    let bytes = fs::read("vault_enc").unwrap();

    let (reading_locked_vault, _): (LockedVault, usize) =
        bincode::decode_from_slice(&bytes, config::standard()).unwrap();
    let unlocked_vault = match reading_locked_vault.unlock_vault(&encryptor) {
        Some(vault) => vault,
        None => panic!("Couldn't unlock vault"),
    };

    println!("Plaintext: {:?}", unlocked_vault);
}
