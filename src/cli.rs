use crate::vault::{Entry, Vault};
use clap::{Parser, Subcommand};
use rpassword;
use std::path::PathBuf;

/// A simple password vault encryption tool
#[derive(Parser, Debug)]
#[command(author, version, about)]
pub struct Cli {
    /// Path to the vault file
    #[arg(short, long, value_name = "FILE")]
    pub vault: Option<PathBuf>,

    /// Choose an action
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Dump the vault
    Show,

    /// Create a new vault
    New,

    /// Add entry to vault
    Add {
        entry_name: String,
        entry_username: String,
        entry_password: Option<String>,
    },

    /// Start REPL
    Repl,

    /// Get an entry
    Get {
        name: String,
    },

    Del {
        name: String,
    },
}

/// Takes an already decrypted vault and performs operations on it
pub fn handle_args(
    cli: Cli,
    vault: &mut Vault,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut has_updated = false;
    match cli.command {
        Commands::Show => {
            println!("{:?}", vault);
        }
        Commands::Add {
            entry_name,
            entry_username,
            entry_password,
        } => {
            let pass = match entry_password {
                Some(p) => p,
                None => rpassword::prompt_password("Password: ")?,
            };

            let new_entry =
                Entry::new(entry_name.clone(), entry_username, pass);

            vault.add(new_entry);
            has_updated = true;
            println!("Entry for '{}' added", entry_name);
        }
        Commands::Get { name } => match vault.get(name.as_str()) {
            Some(entry) => println!("{:?}", entry),
            None => println!("'{}' not found", name),
        },
        Commands::Del { name } => match vault.del(name.as_str()) {
            Some(entry) => {
                println!("Deleted {:?}", entry);
                has_updated = true;
            }
            None => println!("'{}' not found", name),
        },
        Commands::New | Commands::Repl => {
            eprintln!("Unsupported command in REPL mode");
        }
    }
    Ok(has_updated)
}
