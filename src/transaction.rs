use serde::{Deserialize, Serialize};
use secp256k1::{PublicKey, SecretKey, ecdsa::Signature};
use crate::crypto::{sign_message, hash_message};
use crate::error::Result;

/// Represents a transaction in the multisig wallet

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub id: String,
    pub recipient: String,
    pub amount: u64,
    pub metadata: Option<String>,
    pub timestamp: u64,
    pub nonce: u64,
}

impl Transaction {
    /// Create a new transaction

    pub fn new(recipient: String, amount: u64, metadata: Option<String>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let nonce = rand::random::<u64>();
        
        let mut tx = Transaction {
            id: String::new(),
            recipient,
            amount,
            metadata,
            timestamp,
            nonce,
        };
        
        // Generate transaction ID
        tx.id = tx.calculate_id();
        tx
    }
    
    /// Calculate the transaction ID (hash of transaction data)

    fn calculate_id(&self) -> String {
        let data = format!(
            "{}:{}:{}:{}:{}",
            self.recipient,
            self.amount,
            self.metadata.as_deref().unwrap_or(""),
            self.timestamp,
            self.nonce
        );
        hex::encode(hash_message(data.as_bytes()))
    }
    
    /// Serialize the transaction for signing

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
    
    /// Sign the transaction with a private key

    pub fn sign(&self, secret_key: &SecretKey) -> Result<Signature> {
        let message = self.to_bytes();
        sign_message(&message, secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            "recipient_address".to_string(),
            1000,
            Some("Test transaction".to_string()),
        );
        
        assert_eq!(tx.amount, 1000);
        assert!(!tx.id.is_empty());
    }

    #[test]
    fn test_transaction_signing() {
        let (secret_key, _) = generate_keypair().unwrap();
        let tx = Transaction::new(
            "recipient_address".to_string(),
            500,
            None,
        );
        
        let signature = tx.sign(&secret_key);
        assert!(signature.is_ok());
    }

    #[test]
    fn test_transaction_serialization() {
        let tx = Transaction::new(
            "recipient_address".to_string(),
            1000,
            Some("Test".to_string()),
        );
        
        let bytes = tx.to_bytes();
        assert!(!bytes.is_empty());
        
        let deserialized: Transaction = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(tx.id, deserialized.id);
        assert_eq!(tx.amount, deserialized.amount);
    }
}
