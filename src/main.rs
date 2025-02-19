mod cli;
mod encryption;
mod metadataheader;

use clap::Parser;
use cli::Cli;
use cli::Commands;

use encryption::decrypt_file;
use encryption::encrypt_file;

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
            algo,
            ref output,
        } => {
            decrypt_file(path, password, algo, &output).expect("Couldn't decrypt the file.");
        }
    }
}
