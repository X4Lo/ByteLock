use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ByteLock")]
#[command(about = "A simple CLI encryption tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a file or folder
    #[command(alias = "c")]
    Crypt {
        /// Path to the file or folder
        path: String,

        /// Password for encryption
        #[arg(short, long)]
        password: String,

        /// Optional: Specify output path
        #[arg(short, long)]
        output: Option<String>,

        /// Encryption algorithm (default: AES-256-GCM)
        #[arg(short, long, default_value = "AES-256-GCM")]
        algo: String,

        /// Optional: Zip the file before encryption
        #[arg(long)]
        zip: bool,

        /// Optional: Delete original file after encryption
        #[arg(long)]
        delete_original: bool,

        /// Salt size (Allowed values: 16, 32, 64)
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(["16", "32", "64"]), default_value = "32")]
        salt: String,
    },

    /// Decrypt a file
    #[command(alias = "d")]
    Decrypt {
        /// Path to the encrypted file
        path: String,

        /// Password for decryption
        #[arg(short, long)]
        password: String,

        /// Optional: Specify output path
        #[arg(short, long)]
        output: Option<String>,

        /// Encryption algorithm (default: AES-256-GCM)
        #[arg(short, long, default_value = "AES-256-GCM")]
        algo: String,
    },
}
