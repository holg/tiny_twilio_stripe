// --- File: src/utils/crypto.rs ---

// Only compile this file if the 'calendly' feature is enabled
#![cfg(feature = "calendly")]

// --- Imports specific to this module ---
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, AeadCore,
    Nonce // The concrete Nonce type alias for Aes256Gcm
};
// use aes_gcm::aead::generic_array::GenericArray; // May still be needed for Nonce::from_slice if not directly available

// --- Public Encryption/Decryption Functions ---

/// Encrypts plaintext using AES-256-GCM with a random nonce.
/// Prepends the 12-byte nonce to the ciphertext.
/// Key must be exactly 32 bytes.
pub fn encrypt(key_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| format!("Invalid encryption key length: {}", e))?;

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypts data previously encrypted with `encrypt`.
/// Assumes the first 12 bytes are the nonce.
/// Key must be exactly 32 bytes.
pub fn decrypt(key_bytes: &[u8], nonce_ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let nonce_size = 12;
    if nonce_ciphertext.len() <= nonce_size {
        return Err("Ciphertext too short to contain nonce".to_string());
    }

    let cipher = Aes256Gcm::new_from_slice(key_bytes)
        .map_err(|e| format!("Invalid decryption key length: {}", e))?;

    let (nonce_bytes, ciphertext) = nonce_ciphertext.split_at(nonce_size);
    // Use GenericArray here explicitly if Nonce::from_slice causes issues
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed (likely invalid key or ciphertext/tag): {}", e))
}
