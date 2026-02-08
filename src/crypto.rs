use secp256k1::{Secp256k1, SecretKey, PublicKey, Message, ecdsa::Signature};
use rand::rngs::OsRng;
use sha2::{Sha256, Digest};
use crate::error::{MultisigError, Result};

/// Generate a new keypair for signing

pub fn generate_keypair() -> Result<(SecretKey, PublicKey)> {
    let secp = Secp256k1::new();
    let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);
    Ok((secret_key, public_key))
}

/// Sign a message with a private key

pub fn sign_message(message: &[u8], secret_key: &SecretKey) -> Result<Signature> {
    let secp = Secp256k1::new();
    
    // Hash the message
    let hash = hash_message(message);
    let message = Message::from_digest_slice(&hash)
        .map_err(|e| MultisigError::CryptoError(e.to_string()))?;
    
    Ok(secp.sign_ecdsa(&message, secret_key))
}

/// Verify a signature against a public key

pub fn verify_signature(
    message: &[u8],
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<bool> {
    let secp = Secp256k1::new();
    
    // Hash the message

    let hash = hash_message(message);
    let message = Message::from_digest_slice(&hash)
        .map_err(|e| MultisigError::CryptoError(e.to_string()))?;
    
    match secp.verify_ecdsa(&message, signature, public_key) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Hash a message using SHA-256

pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let result = generate_keypair();
        assert!(result.is_ok());
    }

    #[test]
    fn test_sign_and_verify() {
        let (secret_key, public_key) = generate_keypair().unwrap();
        let message = b"Hello, multisig world!";
        
        let signature = sign_message(message, &secret_key).unwrap();
        let is_valid = verify_signature(message, &signature, &public_key).unwrap();
        
        assert!(is_valid);
    }

    #[test]
    fn test_invalid_signature() {
        let (secret_key1, _) = generate_keypair().unwrap();
        let (_, public_key2) = generate_keypair().unwrap();
        let message = b"Test message";
        
        let signature = sign_message(message, &secret_key1).unwrap();
        let is_valid = verify_signature(message, &signature, &public_key2).unwrap();
        
        assert!(!is_valid);
    }
}
