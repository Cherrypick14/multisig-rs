use multisig_rs::{MultisigWallet, Transaction, generate_keypair};

fn main() {
    println!("=== Multisig Wallet Demo ===\n");
    
    // Generate 3 keypairs for a 2-of-3 multisig
    println!("Generating keypairs...");
    let (sk1, pk1) = generate_keypair().expect("Failed to generate keypair 1");
    let (sk2, pk2) = generate_keypair().expect("Failed to generate keypair 2");
    let (sk3, pk3) = generate_keypair().expect("Failed to generate keypair 3");
    
    println!("✓ Generated 3 keypairs\n");
    
    // Create a 2-of-3 multisig wallet
    println!("Creating 2-of-3 multisig wallet...");
    let mut wallet = MultisigWallet::new(2, vec![pk1, pk2, pk3])
        .expect("Failed to create wallet");
    
    let info = wallet.info();
    println!("✓ Wallet created:");
    println!("  - Threshold: {}", info.threshold);
    println!("  - Total signers: {}", info.total_signers);
    println!();
    
    // Create a transaction
    println!("Creating transaction...");
    let recipient = hex::encode(pk3.serialize());
    let tx = Transaction::new(
        recipient,
        1000,
        Some("Test multisig transaction".to_string()),
    );
    
    println!("✓ Transaction created:");
    println!("  - ID: {}", tx.id);
    println!("  - Amount: {}", tx.amount);
    println!("  - Metadata: {}", tx.metadata.as_ref().unwrap());
    println!();
    
    // Propose the transaction
    println!("Proposing transaction...");
    wallet.propose_transaction(tx.clone())
        .expect("Failed to propose transaction");
    println!("✓ Transaction proposed\n");
    
    // Sign with first key
    println!("Signing with key 1...");
    let sig1 = tx.sign(&sk1).expect("Failed to sign");
    wallet.add_signature(&tx.id, sig1, &pk1)
        .expect("Failed to add signature");
    
    let sig_count = wallet.get_signature_count(&tx.id).unwrap();
    println!("✓ Signature added ({}/{})", sig_count, info.threshold);
    println!();
    
    // Check if we have enough signatures
    if !wallet.has_enough_signatures(&tx.id).unwrap() {
        println!("Need more signatures...");
        
        // Sign with second key
        println!("Signing with key 2...");
        let sig2 = tx.sign(&sk2).expect("Failed to sign");
        wallet.add_signature(&tx.id, sig2, &pk2)
            .expect("Failed to add signature");
        
        let sig_count = wallet.get_signature_count(&tx.id).unwrap();
        println!("✓ Signature added ({}/{})", sig_count, info.threshold);
        println!();
    }
    
    // Execute the transaction
    if wallet.has_enough_signatures(&tx.id).unwrap() {
        println!("Executing transaction...");
        let executed_tx = wallet.execute_transaction(&tx.id)
            .expect("Failed to execute transaction");
        
        println!("✓ Transaction executed successfully!");
        println!("  - ID: {}", executed_tx.id);
        println!("  - Amount: {}", executed_tx.amount);
        println!();
    }
    
}
