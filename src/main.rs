use cryptostuff::{
    encryptor::Encryptor,
    vault::{Entry, LockedVault, Vault},
};

use bincode::{self, config};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// A simple password vault encryption tool
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to the vault file
    #[arg(short, long, value_name = "FILE")]
    vault: PathBuf,

    /// Choose an action: encrypt or decrypt
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Decrypt and read the vault
    Show,

    /// Create a new vault
    New,

    /// Add entry to vault
    Add,
}

fn decrypt_vault(
    file_path: &PathBuf,
    password: &String,
) -> (Vault, LockedVault) {
    let bytes = fs::read(file_path).unwrap();
    let (reading_locked_vault, _): (LockedVault, usize) =
        bincode::decode_from_slice(&bytes, config::standard()).unwrap();
    (reading_locked_vault.decrypt(password), reading_locked_vault)
}

fn new_vault(file_path: &PathBuf, password: &String) {
    let vault = Vault::new();
    let encryptor = Encryptor::new(password.as_bytes(), None);
    let locked_vault = LockedVault::from_vault(&encryptor, vault);
    let serialized_locked_vault =
        bincode::encode_to_vec(&locked_vault, config::standard()).unwrap();

    // Write to file
    let mut writing_file = File::create(file_path).unwrap();
    writing_file.write_all(&serialized_locked_vault).unwrap();
}

fn prompt(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().unwrap(); // make sure prompt prints immediately

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");
    input.trim().to_string()
}

fn main() {
    let cli = Cli::parse();

    let password;
    match cli.command {
        Commands::Show => {
            println!("Decrypting vault: {:?}", cli.vault);
            password =
                rpassword::prompt_password("Enter decryption password: ")
                    .unwrap();
            let (vault, _) = decrypt_vault(&cli.vault, &password);
            println!("Vault Contents: {:?}", vault);
        }
        Commands::New => {
            password =
                rpassword::prompt_password("Enter encryption password: ")
                    .unwrap();
            new_vault(&cli.vault, &password);
            println!("Created vault at {:?}", cli.vault);
        }
        Commands::Add => {
            println!("Decrypting vault: {:?}", cli.vault);
            password =
                rpassword::prompt_password("Enter decryption password: ")
                    .unwrap();
            let (mut vault, locked_vault) =
                decrypt_vault(&cli.vault, &password);

            let entry_name = prompt("Name: ");
            let entry_username = prompt("Username: ");
            let entry_password =
                rpassword::prompt_password("Password: ").unwrap();

            let new_entry =
                Entry::new(entry_name, entry_username, entry_password);

            vault.add(new_entry);

            println!("Vault is now {:?}", vault);
            let updated_vault = locked_vault.encrypt_updated(&password, vault);

            let serialized_locked_vault =
                bincode::encode_to_vec(&updated_vault, config::standard())
                    .unwrap();

            // Write to file
            let mut writing_file = File::create(cli.vault).unwrap();
            writing_file.write_all(&serialized_locked_vault).unwrap();
        }
    }
}
