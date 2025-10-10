use clap::{Parser, Subcommand};
use rpassword;
use std::io::{self, Write};
use std::path::PathBuf;

use rspass::vault::{Entry, LockedVault, Vault};

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

    let password =
        rpassword::prompt_password("Enter decryption password: ").unwrap();
    match cli.command {
        Commands::Show => {
            let locked_vault = LockedVault::from_file(&cli.vault);
            let vault = locked_vault.decrypt(&password);
            println!("Vault Contents: {:?}", vault);
        }
        Commands::New => {
            let locked_vault =
                LockedVault::from_vault(Vault::new(), &password, None);
            locked_vault.to_file(&cli.vault);
            println!("Created vault at {:?}", cli.vault);
        }
        Commands::Add => {
            let locked_vault = LockedVault::from_file(&cli.vault);
            let mut vault = locked_vault.decrypt(&password);

            let entry_name = prompt("Name: ");
            let entry_username = prompt("Username: ");
            let entry_password =
                rpassword::prompt_password("Password: ").unwrap();

            let new_entry =
                Entry::new(entry_name.clone(), entry_username, entry_password);

            vault.add(new_entry);

            let updated_vault = locked_vault.encrypt_updated(&password, vault);
            updated_vault.to_file(&cli.vault);
            println!("Entry for '{}' added", entry_name);
        }
    }
}
