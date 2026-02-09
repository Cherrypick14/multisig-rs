use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use secp256k1::{PublicKey, ecdsa::Signature};
use crate::transaction::Transaction;
use crate::crypto::verify_signature;
use crate::error::{MultisigError, Result};

/// Represents a multisig wallet with M-of-N signature requirement

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultisigWallet {
    threshold: usize,
    total_signers: usize,
    
    #[serde(skip)]
    authorized_keys: Vec<PublicKey>,
    authorized_keys_hex: Vec<String>,
    pending_transactions: HashMap<String, PendingTransaction>,
}

/// Represents a transaction awaiting signatures

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingTransaction {
    transaction: Transaction,
    
    signatures: HashMap<String, String>,
    
    executed: bool,
}

impl MultisigWallet {

    /// Create a new multisig wallet

    pub fn new(threshold: usize, authorized_keys: Vec<PublicKey>) -> Result<Self> {
        let total_signers = authorized_keys.len();
        
        // Validate threshold

        if threshold == 0 || threshold > total_signers {
            return Err(MultisigError::InvalidThreshold {
                m: threshold,
                n: total_signers,
            });
        }
        
        // Convert public keys to hex for serialization

        let authorized_keys_hex: Vec<String> = authorized_keys
            .iter()
            .map(|pk| hex::encode(pk.serialize()))
            .collect();
        
        Ok(MultisigWallet {
            threshold,
            total_signers,
            authorized_keys,
            authorized_keys_hex,
            pending_transactions: HashMap::new(),
        })
    }
    
    /// Propose a new transaction

    pub fn propose_transaction(&mut self, transaction: Transaction) -> Result<()> {
        let tx_id = transaction.id.clone();
        
        let pending = PendingTransaction {
            transaction,
            signatures: HashMap::new(),
            executed: false,
        };
        
        self.pending_transactions.insert(tx_id, pending);
        Ok(())
    }
    
    /// Add a signature to a pending transaction

    pub fn add_signature(
        &mut self,
        tx_id: &str,
        signature: Signature,
        signer_pubkey: &PublicKey,
    ) -> Result<()> {

        // Check if signer is authorized
        if !self.is_authorized(signer_pubkey) {
            return Err(MultisigError::UnauthorizedSigner);
        }
        
        // Get the pending transaction
        let pending = self.pending_transactions
            .get_mut(tx_id)
            .ok_or(MultisigError::TransactionNotFound)?;
        
        // Check if already executed
        if pending.executed {
            return Err(MultisigError::TransactionAlreadyExecuted);
        }
        
        // Verify the signature
        let tx_bytes = pending.transaction.to_bytes();
        let is_valid = verify_signature(&tx_bytes, &signature, signer_pubkey)?;
        
        if !is_valid {
            return Err(MultisigError::InvalidSignature);
        }
        
        // Store the signature
        let pubkey_hex = hex::encode(signer_pubkey.serialize());
        let sig_hex = hex::encode(signature.serialize_compact());
        
        // Check for duplicate signature
        if pending.signatures.contains_key(&pubkey_hex) {
            return Err(MultisigError::DuplicateSignature);
        }
        
        pending.signatures.insert(pubkey_hex, sig_hex);
        
        Ok(())
    }
    
    /// Check if a transaction has enough signatures

    pub fn has_enough_signatures(&self, tx_id: &str) -> Result<bool> {
        let pending = self.pending_transactions
            .get(tx_id)
            .ok_or(MultisigError::TransactionNotFound)?;
        
        Ok(pending.signatures.len() >= self.threshold)
    }
    
    /// Verify and execute a transaction if it has enough signatures

    pub fn execute_transaction(&mut self, tx_id: &str) -> Result<Transaction> {
        if !self.has_enough_signatures(tx_id)? {
            let pending = self.pending_transactions.get(tx_id).unwrap();
            return Err(MultisigError::InsufficientSignatures {
                required: self.threshold,
                actual: pending.signatures.len(),
            });
        }
        
        let pending = self.pending_transactions
            .get_mut(tx_id)
            .ok_or(MultisigError::TransactionNotFound)?;
        
        if pending.executed {
            return Err(MultisigError::TransactionAlreadyExecuted);
        }
        
        pending.executed = true;
        
        
        Ok(pending.transaction.clone())
    }
    
    /// Check if a public key is authorized

    fn is_authorized(&self, pubkey: &PublicKey) -> bool {
        self.authorized_keys.iter().any(|pk| pk == pubkey)
    }
    
    /// Get the number of signatures for a transaction

    pub fn get_signature_count(&self, tx_id: &str) -> Result<usize> {
        let pending = self.pending_transactions
            .get(tx_id)
            .ok_or(MultisigError::TransactionNotFound)?;
        
        Ok(pending.signatures.len())
    }
    
    /// Get wallet information

    pub fn info(&self) -> WalletInfo {
        WalletInfo {
            threshold: self.threshold,
            total_signers: self.total_signers,
            pending_count: self.pending_transactions.len(),
        }
    }
}


#[derive(Debug, Serialize, Deserialize)]
pub struct WalletInfo {
    pub threshold: usize,
    pub total_signers: usize,
    pub pending_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;

    #[test]
    fn test_wallet_creation() {
        let (_, pk1) = generate_keypair().unwrap();
        let (_, pk2) = generate_keypair().unwrap();
        let (_, pk3) = generate_keypair().unwrap();
        
        let wallet = MultisigWallet::new(2, vec![pk1, pk2, pk3]);
        assert!(wallet.is_ok());
        
        let wallet = wallet.unwrap();
        assert_eq!(wallet.threshold, 2);
        assert_eq!(wallet.total_signers, 3);
    }

    #[test]
    fn test_invalid_threshold() {
        let (_, pk1) = generate_keypair().unwrap();
        
        let wallet = MultisigWallet::new(2, vec![pk1]);
        assert!(wallet.is_err());
    }

    #[test]
    fn test_transaction_flow() {
        let (sk1, pk1) = generate_keypair().unwrap();
        let (sk2, pk2) = generate_keypair().unwrap();
        let (_, pk3) = generate_keypair().unwrap();
        
        let mut wallet = MultisigWallet::new(2, vec![pk1, pk2, pk3]).unwrap();
        
        let tx = Transaction::new("recipient".to_string(), 1000, None);
        let tx_id = tx.id.clone();
        
        wallet.propose_transaction(tx.clone()).unwrap();
        
        // Add first signature
        let sig1 = tx.sign(&sk1).unwrap();
        wallet.add_signature(&tx_id, sig1, &pk1).unwrap();
        
        assert!(!wallet.has_enough_signatures(&tx_id).unwrap());
        
        // Add second signature
        let sig2 = tx.sign(&sk2).unwrap();
        wallet.add_signature(&tx_id, sig2, &pk2).unwrap();
        
        assert!(wallet.has_enough_signatures(&tx_id).unwrap());
        
        // Execute transaction
        let executed = wallet.execute_transaction(&tx_id);
        assert!(executed.is_ok());
    }
}
