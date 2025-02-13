mod cli;

use clap::Parser;
use cli::Cli;
use cli::Commands;

static DEBUG: bool = true;

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Crypt {
            path,
            password,
            output,
            algo,
            zip,
            delete_original,
            salt,
        } => {
            if DEBUG {
                println!("------------- DEBUG -------------");
                println!("Encrypting file: {}", path);
                println!("Using password: {}", password);
                if let Some(output_path) = output {
                    println!("Output path: {}", output_path);
                }
                if zip {
                    println!("Compression enabled.");
                }
                if delete_original {
                    println!("Original file will be deleted.");
                }
                let salt_size: u16 = salt.parse().unwrap();
                println!("Algorithm: {}", algo);
                println!("Salt Size: {}", salt_size);
                println!("----------- EOF DEBUG -----------");
            }

            // TODO: encryption logic
        }
        Commands::Decrypt {
            path,
            password,
            output,
        } => {
            if DEBUG {
                println!("------------- DEBUG -------------");
                println!("Encrypting file: {}", path);
                println!("Using password: {}", password);
                if let Some(output_path) = output {
                    println!("Output path: {}", output_path);
                }
                println!("----------- EOF DEBUG -----------");
            }

            // TODO: decryption logic
        }
    }
}

