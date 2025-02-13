# ByteLock - A File Encryption CLI Tool

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Commands](#commands)
6. [Examples](#examples)
7. [Contributing](#contributing)
8. [License](#license)

## Introduction

`ByteLock.exe` is a command-line tool written in Rust for encrypting and decrypting files. It supports various encryption algorithms, optional ZIP compression, and custom output paths. The tool uses a custom binary format for storing metadata securely, making it harder for unauthorized users to interpret the encrypted data.

## Features

- **Encryption and Decryption**: Securely encrypt and decrypt files using passwords.
- **ZIP Compression**: Optionally compress files before encryption.
- **Custom Output Paths**: Save encrypted or decrypted files to a specified location.
- **Delete Original Files**: Automatically delete the original file after encryption or decryption.
- **Algorithm Selection**: Choose from multiple encryption algorithms (e.g., AES, ChaCha20).
- **Custom Binary Format**: Metadata is stored in a compact, secure binary format.

## Installation

### Prerequisites
- Rust and Cargo installed on your system. You can install them from [rustup.rs](https://rustup.rs/).

### Building from Source
1. Clone the repository:
```bash
git clone https://github.com/your-repo/crypt.git
cd crypt
```
2. Build the project:
```bash
cargo build --release
```
3. The executable will be located in `target/release/ByteLock.exe`.

### Using Precompiled Binaries
Download the latest release from the [releases page](https://github.com/your-repo/crypt/releases) and place it in your system's PATH.


## Usage

The general syntax for using `ByteLock.exe` is:

```bash
ByteLock.exe <command> [options]
```

Run the tool with the `--help` flag to see all available options:

```bash
ByteLock.exe --help
```

## Commands

### Encryption (`--crypt`)
Encrypts a file using a password.

#### Options:
- `--password <password>`: The password used for encryption.
- `--zip`: Compress the file using ZIP before encryption.
- `--output <output-path>`: Specify the output path for the encrypted file.
- `--delete-original`: Delete the original file after encryption.
- `--algo <algo>`: Specify the encryption algorithm (default: AES).

#### Example:
```bash
ByteLock.exe --crypt --password mysecurepassword --zip --output encrypted_file.bin input_file.txt
```

### Decryption (`--decrypt`)
Decrypts a file using a password.

#### Options:
- `--password <password>`: The password used for decryption.
- `--output <output-path>`: Specify the output path for the decrypted file.

#### Example:
```bash
ByteLock.exe --decrypt --password mysecurepassword --output decrypted_file.txt encrypted_file.bin
```

## Examples

### Encrypt a File
Encrypt a file named `data.txt` using the password `mysecurepassword`:
```bash
ByteLock.exe --crypt --password mysecurepassword data.txt
```

### Encrypt and Compress a File
Encrypt and compress a file named `data.txt` using the password `mysecurepassword`:
```bash
ByteLock.exe --crypt --password mysecurepassword --zip data.txt
```

### Encrypt and Save to a Custom Output Path
Encrypt a file named `data.txt` and save the result as `encrypted_data.bin`:
```bash
ByteLock.exe --crypt --password mysecurepassword --output encrypted_data.bin data.txt
```

### Delete the Original File After Encryption
Encrypt a file named `data.txt` and delete the original file:
```bash
ByteLock.exe --crypt --password mysecurepassword --delete-original data.txt
```

### Decrypt a File
Decrypt a file named `encrypted_data.bin` using the password `mysecurepassword`:
```bash
ByteLock.exe --decrypt --password mysecurepassword encrypted_data.bin
```

### Decrypt and Save to a Custom Output Path
Decrypt a file named `encrypted_data.bin` and save the result as `decrypted_data.txt`:
```bash
ByteLock.exe --decrypt --password mysecurepassword --output decrypted_data.txt encrypted_data.bin
```

## Contributing

 Contributions are welcome! If you'd like to contribute, please fork the repository and create a pull request. For major changes, please open an issue first to discuss what you'd like to change.

## Acknowledgments

- Thanks to the Rust community for creating such a powerful and safe programming language.
- Special thanks to the creators of cryptographic libraries and tools used in this project.
