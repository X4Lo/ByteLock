#[derive(Debug, Clone)]
pub struct MetadataHeader {
    pub magic: [u8; 8],     // Magic number to identify the file type ("ByteLock")
    pub version: u16,       // Version of the metadata format
    pub salt_len: u8,       // Explicitly store salt length
    pub salt: Vec<u8>,      // Variable-length salt used for key derivation (16, 32, or 64 bytes)
    pub nonce_len: u8,      // Explicitly store nonce length
    pub nonce: Vec<u8>,     // Variable-length nonce used for encryption
    pub original_size: u64, // Size of the original plaintext file
    pub algo_type_len: u8,  // Length of the algorithm type string
    pub algo_type: String,  // Algorithm type (e.g., "AES-256-GCM", "ChaCha20-Poly1305")
}

impl MetadataHeader {
    pub fn new(salt: Vec<u8>, nonce: Vec<u8>, original_size: u64, algo_type: String) -> Self {
        assert!(
            salt.len() == 16 || salt.len() == 32 || salt.len() == 64,
            "Salt size must be 16, 32, or 64 bytes"
        );
        assert!(
            nonce.len() >= 12 && nonce.len() <= 24,
            "Nonce size must be between 12 and 24 bytes"
        );
        MetadataHeader {
            magic: *b"ByteLock",
            version: 1,
            salt_len: salt.len() as u8,
            salt,
            nonce_len: nonce.len() as u8,
            nonce,
            original_size,
            algo_type_len: algo_type.len() as u8,
            algo_type,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buffer: Vec<u8> = Vec::new();
        buffer.extend_from_slice(&self.magic);
        buffer.extend_from_slice(&self.version.to_le_bytes());
        buffer.push(self.salt_len);
        buffer.extend_from_slice(&self.salt);
        buffer.push(self.nonce_len);
        buffer.extend_from_slice(&self.nonce);
        buffer.extend_from_slice(&self.original_size.to_le_bytes());
        buffer.push(self.algo_type_len);
        buffer.extend_from_slice(self.algo_type.as_bytes());
        buffer
    }

    pub fn deserialize(data: &[u8]) -> Option<Self> {
        if data.len() < 10 {
            return None;
        }
        let mut read_pos = 0;

        let magic: [u8; 8] = data[read_pos..8].try_into().unwrap();
        if magic != *b"ByteLock" {
            return None;
        }
        read_pos += 8;

        let version = u16::from_le_bytes(data[read_pos..(read_pos + 2)].try_into().unwrap());
        read_pos += 2;

        let salt_len = data[read_pos] as usize;
        if !(salt_len == 16 || salt_len == 32 || salt_len == 64)
            || data.len() < read_pos + 1 + salt_len
        {
            return None;
        }
        read_pos += 1;

        let salt = data[read_pos..(read_pos + salt_len)].to_vec();
        read_pos += salt_len;

        let nonce_len = data[read_pos] as usize;
        if nonce_len < 12 || nonce_len > 24 || data.len() < read_pos + 1 + nonce_len {
            return None;
        }
        read_pos += 1;

        let nonce = data[read_pos..(read_pos + nonce_len)].to_vec();
        read_pos += nonce_len;

        let original_size = u64::from_le_bytes(data[read_pos..(read_pos + 8)].try_into().unwrap());
        read_pos += 8;

        let algo_type_len = data[read_pos] as usize;
        read_pos += 1;
        
        if data.len() < read_pos + algo_type_len {
            return None;
        }
        let algo_type =
            String::from_utf8_lossy(&data[read_pos..(read_pos + algo_type_len)]).to_string();

        Some(MetadataHeader {
            magic,
            version,
            salt_len: salt_len as u8,
            salt,
            nonce_len: nonce_len as u8,
            nonce,
            original_size,
            algo_type_len: algo_type_len as u8,
            algo_type,
        })
    }
}
