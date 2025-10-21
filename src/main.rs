use clap::Parser;
use rpassword;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;

use rspass::cli::{Cli, Commands, handle_args};
use rspass::vault::{LockedVault, Vault};

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
        println!("Writing changes to {:?}", &vault_file);
        let updated_vault = locked_vault.encrypt_updated(&password, vault)?;
        updated_vault.to_file(&vault_file)?;
    }
    Ok(())
}
