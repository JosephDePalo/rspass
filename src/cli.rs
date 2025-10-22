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
        name: String,

        #[arg(short, long)]
        username: String,

        #[arg(short, long)]
        password: Option<String>,
    },

    /// Start REPL
    Repl,

    /// Get an entry
    Get {
        name: String,

        #[arg(short, long)]
        show_secrets: bool,
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
            println!("{}", vault);
        }
        Commands::Add {
            name,
            username,
            password,
        } => {
            let pass = match password {
                Some(p) => p,
                None => rpassword::prompt_password("Password: ")?,
            };

            let new_entry = Entry::new(name.clone(), username, pass);

            if let Err(e) = vault.add(new_entry) {
                eprintln!("{}", e);
            } else {
                has_updated = true;
                println!("Entry for '{}' added", name);
            }
        }
        Commands::Get { name, show_secrets } => {
            match vault.get(name.as_str()) {
                Some(entry) => entry.print(show_secrets),
                None => println!("'{}' not found", name),
            }
        }
        Commands::Del { name } => match vault.del(name.as_str()) {
            Some(entry) => {
                println!("Deleted {}", entry);
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
