use multisig_rs::{MultisigWallet, Transaction, generate_keypair};

#[test]
fn test_complete_multisig_workflow() {
    // Generate the  keypairs
    let (sk1, pk1) = generate_keypair().unwrap();
    let (sk2, pk2) = generate_keypair().unwrap();
    let (sk3, pk3) = generate_keypair().unwrap();
    
    // Create 2-of-3 wallet. 
    let mut wallet = MultisigWallet::new(2, vec![pk1, pk2, pk3]).unwrap();
    
    // Create and propose a transaction. 
    let tx = Transaction::new("recipient".to_string(), 5000, Some("Integration test".to_string()));
    let tx_id = tx.id.clone();
    
    wallet.propose_transaction(tx.clone()).unwrap();
    
    // Add the signatures.
    let sig1 = tx.sign(&sk1).unwrap();
    wallet.add_signature(&tx_id, sig1, &pk1).unwrap();
    
    let sig2 = tx.sign(&sk2).unwrap();
    wallet.add_signature(&tx_id, sig2, &pk2).unwrap();
    
    // Execute
    let result = wallet.execute_transaction(&tx_id);
    assert!(result.is_ok());
}

#[test]
fn test_insufficient_signatures() {
    let (sk1, pk1) = generate_keypair().unwrap();
    let (_, pk2) = generate_keypair().unwrap();
    let (_, pk3) = generate_keypair().unwrap();
    
    let mut wallet = MultisigWallet::new(2, vec![pk1, pk2, pk3]).unwrap();
    
    let tx = Transaction::new("recipient".to_string(), 1000, None);
    let tx_id = tx.id.clone();
    
    wallet.propose_transaction(tx.clone()).unwrap();
    
    // Only one signature
    let sig1 = tx.sign(&sk1).unwrap();
    wallet.add_signature(&tx_id, sig1, &pk1).unwrap();
    
    // Should fail to execute
    let result = wallet.execute_transaction(&tx_id);
    assert!(result.is_err());
}

#[test]
fn test_unauthorized_signer() {
    let (_, pk1) = generate_keypair().unwrap();
    let (_, pk2) = generate_keypair().unwrap();
    let (sk_unauthorized, pk_unauthorized) = generate_keypair().unwrap();
    
    let mut wallet = MultisigWallet::new(2, vec![pk1, pk2]).unwrap();
    
    let tx = Transaction::new("recipient".to_string(), 1000, None);
    let tx_id = tx.id.clone();
    
    wallet.propose_transaction(tx.clone()).unwrap();
    
    // Try to sign with unauthorized key
    let sig = tx.sign(&sk_unauthorized).unwrap();
    let result = wallet.add_signature(&tx_id, sig, &pk_unauthorized);
    
    assert!(result.is_err());
}
