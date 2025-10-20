use clap::{Parser, Subcommand};
use rpassword;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
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

    /// Start REPL
    Repl,
}

fn prompt(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    print!("{}", prompt);
    io::stdout().flush()?; // make sure prompt prints immediately

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let password = rpassword::prompt_password("Enter decryption password: ")?;
    match cli.command {
        Commands::Show => {
            let locked_vault = LockedVault::from_file(&cli.vault)?;
            let vault = locked_vault.decrypt(&password)?;
            println!("Vault Contents: {:?}", vault);
        }
        Commands::New => {
            let locked_vault =
                LockedVault::from_vault(Vault::new(), &password, None)?;
            locked_vault.to_file(&cli.vault)?;
            println!("Created vault at {:?}", cli.vault);
        }
        Commands::Add => {
            let locked_vault = LockedVault::from_file(&cli.vault)?;
            let mut vault = locked_vault.decrypt(&password)?;

            let entry_name = prompt("Name: ")?;
            let entry_username = prompt("Username: ")?;
            let entry_password = rpassword::prompt_password("Password: ")?;

            let new_entry =
                Entry::new(entry_name.clone(), entry_username, entry_password);

            vault.add(new_entry);

            let updated_vault =
                locked_vault.encrypt_updated(&password, vault)?;
            updated_vault.to_file(&cli.vault)?;
            println!("Entry for '{}' added", entry_name);
        }
        Commands::Repl => {
            let locked_vault = LockedVault::from_file(&cli.vault)?;
            let mut vault = locked_vault.decrypt(&password)?;
            let mut rl = DefaultEditor::new()?;
            let mut updated = false;

            loop {
                let readline = rl.readline(">> ");
                match readline {
                    Ok(line) => {
                        let mut parts = line.split_whitespace();
                        let Some(subcmd) = parts.next() else {
                            continue;
                        };
                        match subcmd {
                            "show" => println!("{:?}", &vault),
                            "add" => {
                                let add_args: Vec<&str> = parts.collect();
                                if add_args.len() != 3 {
                                    println!("Bad usage of add");
                                    continue;
                                }
                                vault.add(Entry::new(
                                    add_args[0].to_string(),
                                    add_args[1].to_string(),
                                    add_args[2].to_string(),
                                ));
                                println!("Added entry '{}'", add_args[0]);
                                updated = true;
                            }
                            "get" => {
                                let get_args: Vec<&str> = parts.collect();
                                if get_args.len() != 1 {
                                    println!("Bad usage of get");
                                    continue;
                                }
                                match vault.get(get_args[0]) {
                                    Some(entry) => println!("{:?}", entry),
                                    None => {
                                        println!("'{}' not found", get_args[0])
                                    }
                                }
                            }
                            "quit" => break,
                            _ => (),
                        }
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

            if updated {
                let updated_vault =
                    locked_vault.encrypt_updated(&password, vault)?;
                updated_vault.to_file(&cli.vault)?;
            }
        }
    }

    Ok(())
}
