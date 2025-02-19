mod cli;
mod encryption;
mod metadataheader;

use clap::Parser;
use cli::Cli;
use cli::Commands;

use encryption::decrypt_file;
use encryption::encrypt_file;

static DEBUG: bool = true;

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Crypt {
            path,
            password,
            algo,
            salt,
            zip,
            ref output,
            delete_original,
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

            encrypt_file(
                path,
                password,
                algo,
                salt.parse().unwrap(),
                zip,
                &output,
                delete_original,
            );
        }
        Commands::Decrypt {
            path,
            password,
            ref output,
        } => {
            if DEBUG {
                println!("------------- DEBUG -------------");
                println!("Decrypting file: {}", path);
                println!("Using password: {}", password);
                if let Some(output_path) = output {
                    println!("Output path: {}", output_path);
                }
                println!("----------- EOF DEBUG -----------");
            }

            decrypt_file(path, password, &output).expect("Couldn't decrypt the file.");
        }
    }
}
