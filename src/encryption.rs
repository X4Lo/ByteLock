use crate::metadataheader::MetadataHeader;
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305};
use ring::rand::{SecureRandom, SystemRandom};
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

static DEBUG: bool = false;

/// Encrypts a file using the specified encryption algorithm.
///
/// # Arguments
/// * `path` - The path to the file to encrypt.
/// * `password` - The password used for key derivation.
/// * `algo` - The encryption algorithm to use (e.g., "AES-256-GCM", "ChaCha20-Poly1305").
/// * `salt` - The size of the salt in bytes.
/// * `zip` - Whether to compress the file before encryption (not implemented yet).
/// * `output` - Optional output file path.
/// * `delete_original` - Whether to delete the original file after encryption.
pub fn encrypt_file(
    path: String,
    password: String,
    algo: String,
    salt: u16,
    zip: bool,
    output: &Option<String>,
    delete_original: bool,
) {
    if DEBUG {
        println!("------------- DEBUG -------------");
        println!("Encrypting file: {}", path);
        println!("Using password: {}", password);
        println!("Algorithm: {}", algo);
        println!("Salt Size: {}", salt);
        println!("Zip Enabled: {}", zip);
        println!("Output Path: {:?}", output);
        println!("Delete Original: {}", delete_original);
        println!("---------------------------------");
    }

    // 1. Validate file existence and ensure it's not a directory.
    if !Path::new(&path).exists() {
        eprintln!("Error: File does not exist at path: {}", path);
        return;
    }
    let metadata = fs::metadata(&path)
        .unwrap_or_else(|_| panic!("Failed to read metadata for file: {}", path));
    if !metadata.is_file() {
        eprintln!("Error: Only files are supported.");
        return;
    }

    println!("Reading file content...");

    // 2. Read file content (compression is not implemented yet).
    if zip {}
    let data = fs::read(&path).unwrap_or_else(|_| panic!("Failed to read file: {}", path));

    if DEBUG {
        println!("Generating cryptographic materials...");
    }

    // 3. Generate cryptographic materials (salt, nonce, keys).
    let salt_vec = generate_salt(salt as usize);
    // let salt_str = to_hex_string(&salt_vec);
    let nonce = generate_nonce(12).expect("Failed to generate nonce");
    let key = derive_key(&password, &salt_vec);

    let metadata_nonce = generate_nonce(12).expect("Failed to generate metadata nonce");
    let metadata_key = derive_key(&password, "TH!Si5@def4ultS4lt98855".as_bytes());

    // 4. Create and serialize the MetadataHeader.
    let metadata = MetadataHeader::new(salt_vec, nonce.clone(), data.len() as u64, algo.clone());
    let serialized_metadata = metadata.serialize();

    if DEBUG {
        println!("Encrypting metadata...");
    }

    // 5. Encrypt the metadata and the file content.
    let encrypted_metadata = encrypt(
        &metadata_key,
        &metadata_nonce,
        &serialized_metadata,
        "AES-256-GCM",
    )
    .expect("Failed to encrypt metadata");

    println!("Encrypting file content...");

    // Create a progress bar for file encryption
    let pb = ProgressBar::new(data.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
            .unwrap(),
    );

    // Encrypt the file content in chunks to update the progress bar
    let chunk_size = 1024 * 1024; // Process 1 MB at a time
    let mut ciphertext = Vec::new();
    for chunk in data.chunks(chunk_size) {
        let encrypted_chunk = encrypt(&key, &nonce, chunk, &algo).expect("Failed to encrypt chunk");
        ciphertext.extend_from_slice(&encrypted_chunk);
        pb.inc(chunk.len() as u64); // Update progress bar
    }
    pb.finish_with_message("Encryption complete");

    if DEBUG {
        println!("Writing encrypted data to output file...");
    }

    // 6. Write the encrypted data to the output file.
    let output_path = output.clone().unwrap_or_else(|| path.clone());
    let output_file_name = format!("{}.bytelock", output_path);

    let mut output_file =
        fs::File::create(&output_file_name).expect("Failed to create output file");

    output_file
        .write_all(&metadata_nonce)
        .expect("Failed to write metadata nonce");
    output_file
        .write_all(&(encrypted_metadata.len() as u32).to_le_bytes())
        .expect("Failed to write metadata length");
    output_file
        .write_all(&encrypted_metadata)
        .expect("Failed to write encrypted metadata");
    output_file
        .write_all(&ciphertext)
        .expect("Failed to write ciphertext");

    println!("File encrypted successfully: {}", output_file_name);

    // 7. Optionally delete the original file.
    if delete_original {
        if let Err(e) = fs::remove_file(&path) {
            eprintln!("Failed to delete original file: {}", e);
        } else {
            println!("Original file deleted.");
        }
    }
}

/// Decrypts an encrypted file.
///
/// # Arguments
/// * `path` - The path to the encrypted file.
/// * `password` - The password used for decryption.
/// * `output` - Optional output file path.
pub fn decrypt_file(
    path: String,
    password: String,
    algo: String,
    output: &Option<String>,
) -> Result<(), io::Error> {
    if DEBUG {
        println!("------------- DEBUG -------------");
        println!("Decrypting file: {}", path);
        println!("Using password: {}", password);
        println!("Algorithm: {}", algo);
        println!("Output Path: {:?}", output);
        println!("---------------------------------");
    }

    // 1. Validate file existence and ensure it's not a directory.
    if !Path::new(&path).exists() {
        eprintln!("Error: File does not exist at path: {}", path);
        return Ok(());
    }
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        eprintln!("Error: Only files are supported.");
        return Ok(());
    }

    println!("Reading encrypted file...");

    // 2. Read the entire encrypted file into memory.
    let mut input_file = fs::File::open(&path)?;
    let mut buffer = Vec::new();
    input_file.read_to_end(&mut buffer)?;

    if DEBUG {
        println!("Extracting metadata...");
    }

    // 3. Extract metadata nonce (first 12 bytes).
    let metadata_nonce: [u8; 12] = buffer[..12]
        .try_into()
        .map_err(|_| "Error: Invalid metadata nonce")
        .unwrap();
    let buffer = &buffer[12..];

    // 4. Extract metadata length (next 4 bytes).
    let metadata_len: u32 = u32::from_le_bytes(
        buffer[..4]
            .try_into()
            .map_err(|_| "Error: Invalid metadata length")
            .unwrap(),
    );
    let buffer = &buffer[4..];

    // 5. Extract encrypted metadata.
    let encrypted_metadata = &buffer[..metadata_len as usize];
    let buffer = &buffer[metadata_len as usize..];

    if DEBUG {
        println!("Decrypting metadata...");
    }

    // 6. Decrypt the metadata to retrieve the MetadataHeader.
    let metadata_key = derive_key(&password, "TH!Si5@def4ultS4lt98855".as_bytes());
    let decrypted_metadata = decrypt(
        &metadata_key,
        &metadata_nonce,
        encrypted_metadata,
        "AES-256-GCM",
    )?;
    let metadata = MetadataHeader::deserialize(&decrypted_metadata)
        .ok_or("Error: Failed to deserialize metadata")
        .unwrap();

    // 7. Derive the key for decrypting the file content.
    let key = derive_key(&password, &metadata.salt);

    println!("Decrypting file content...");

    // Create a progress bar for file decryption
    let pb = ProgressBar::new(buffer.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {bytes}/{total_bytes} ({eta})")
            .unwrap(),
    );

    // Determine the authentication tag size
    let tag_size = match algo.as_str() {
        "AES-256-GCM" => 16,       // AES-GCM uses a 16-byte tag
        "ChaCha20-Poly1305" => 16, // ChaCha20-Poly1305 also uses a 16-byte tag
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Unsupported algorithm",
            ))
        }
    };

    // Decrypt the file content in chunks to update the progress bar
    let chunk_size = 1024 * 1024 + tag_size; // Process 1 MB at a time
    let mut plaintext = Vec::new();

    for chunk in buffer.chunks(chunk_size) {
        let decrypted_chunk = decrypt(&key, &metadata.nonce, chunk, &algo)?;
        plaintext.extend_from_slice(&decrypted_chunk);
        pb.inc(chunk.len() as u64); // Update progress bar
    }
    pb.finish_with_message("Decryption complete");

    if DEBUG {
        println!("Writing decrypted data to output file...");
    }

    // 9. Write the decrypted content to the output file.
    let output_path = output
        .clone()
        .unwrap_or_else(|| format!("dec_{}", path.replace("./", "")));
    fs::write(&output_path, &plaintext)?;

    println!("File decrypted successfully: {}", output_path);
    Ok(())
}

/// Generates a random salt of the specified size.
fn generate_salt(size: usize) -> Vec<u8> {
    let mut salt = vec![0u8; size];
    rand::thread_rng().fill(&mut salt[..]);
    salt
}

/// Generates a cryptographically secure nonce of the specified length.
///
/// # Arguments
/// * `nonce_len` - The length of the nonce in bytes.
///
/// # Returns
/// A vector containing the generated nonce or an error message if the length is invalid.
fn generate_nonce(nonce_len: usize) -> Result<Vec<u8>, &'static str> {
    if nonce_len == 0 {
        return Err("Error: Nonce length must be greater than zero");
    }
    let rng = SystemRandom::new();
    let mut nonce = vec![0u8; nonce_len];
    rng.fill(&mut nonce)
        .map_err(|_| "Error: Failed to generate nonce")?;
    Ok(nonce)
}

/// Derives a cryptographic key from a password and optional salt.
fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let params = argon2::ParamsBuilder::new()
        .m_cost(16 * 1024) // Memory cost
        .t_cost(4) // Time cost
        .p_cost(1) // Parallelism
        .build()
        .unwrap();

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    // Encode the raw salt bytes into a SaltString
    let salt_string = SaltString::encode_b64(salt).expect("Failed to encode salt");
    // println!("Encoded Salt: {}", salt_string);

    // Hash the password with the encoded salt
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt_string)
        .expect("Failed to hash password");

    password_hash.hash.unwrap().as_ref().to_vec()
}

/// Encrypts plaintext data using the specified algorithm.
fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8], algo: &str) -> Result<Vec<u8>, io::Error> {
    let sealing_key = match algo {
        "AES-256-GCM" => {
            let unbound_key = UnboundKey::new(&AES_256_GCM, key)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid key"))?;
            LessSafeKey::new(unbound_key)
        }
        "ChaCha20-Poly1305" => {
            let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid key"))?;
            LessSafeKey::new(unbound_key)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Error: Unsupported algorithm",
            ))
        }
    };

    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid nonce"))?;

    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Encryption failed"))?;

    in_out.extend_from_slice(tag.as_ref());
    Ok(in_out)
}

/// Decrypts ciphertext data using the specified algorithm.
fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8], algo: &str) -> Result<Vec<u8>, io::Error> {
    let opening_key = match algo {
        "AES-256-GCM" => {
            let unbound_key = UnboundKey::new(&AES_256_GCM, key)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid key"))?;
            LessSafeKey::new(unbound_key)
        }
        "ChaCha20-Poly1305" => {
            let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid key"))?;
            LessSafeKey::new(unbound_key)
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Error: Unsupported algorithm",
            ))
        }
    };

    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Invalid nonce"))?;

    let mut ciphertext = ciphertext.to_vec();
    let plaintext_len = opening_key
        .open_in_place(nonce, Aad::empty(), &mut ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Error: Decryption failed"))?
        .len();

    ciphertext.truncate(plaintext_len);
    Ok(ciphertext)
}
