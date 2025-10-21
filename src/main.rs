use clap::{Parser, Subcommand};
use rpassword;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::path::PathBuf;

use rspass::vault::{Entry, LockedVault, Vault};

/// A simple password vault encryption tool
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Path to the vault file
    #[arg(short, long, value_name = "FILE")]
    vault: Option<PathBuf>,

    /// Choose an action
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
struct ReplCli {
    /// Choose an action
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
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
    Get { name: String },
}

/// Takes an already decrypted vault and performs operations on it
fn handle_args(
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
        Commands::New | Commands::Repl => {
            eprintln!("Unsupported command in REPL mode");
        }
    }
    Ok(has_updated)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let Some(vault_file) = &cli.vault.clone() else {
        eprintln!("Need to provide a value for --vault");
        return Err(Box::new(clap::Error::new(
            clap::error::ErrorKind::MissingRequiredArgument,
        )));
    };
    let password = rpassword::prompt_password("Enter decryption password: ")?;

    let locked_vault;
    let mut vault;
    let mut updated = false;

    match cli.command {
        Commands::New => {
            locked_vault =
                LockedVault::from_vault(Vault::new(), &password, None)?;
            locked_vault.to_file(&vault_file)?;
            println!("Created vault at {:?}", vault_file);
            return Ok(());
        }
        Commands::Repl => {
            locked_vault = LockedVault::from_file(&vault_file)?;
            vault = locked_vault.decrypt(&password)?;
            let mut rl = DefaultEditor::new()?;

            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        let mut args: Vec<&str> =
                            line.split_whitespace().collect();
                        args.insert(0, "");
                        let cli = Cli::parse_from(args);
                        updated = handle_args(cli, &mut vault)?;
                    }
                    Err(ReadlineError::Interrupted) => {
                        break;
                    }
                    Err(ReadlineError::Eof) => {
                        break;
                    }
                    Err(err) => {
                        eprintln!("Error: {:?}", err);
                        break;
                    }
                }
            }
        }
        _ => {
            locked_vault = LockedVault::from_file(&vault_file)?;
            vault = locked_vault.decrypt(&password)?;
            updated = handle_args(cli, &mut vault)?;
        }
    }

    if updated {
        let updated_vault = locked_vault.encrypt_updated(&password, vault)?;
        updated_vault.to_file(&vault_file)?;
        println!("Wrote changes to {:?}", &vault_file);
    }
    Ok(())
}
