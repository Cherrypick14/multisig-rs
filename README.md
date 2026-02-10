# multisig-rs

A multisig wallet implementation in Rust using secp256k1 for transaction signing and verification. This project explores cryptographic primitives, threshold signatures, and robust error handling in blockchain applications.

## Overview

This project implements a **multi-signature (multisig) wallet** where multiple parties must approve a transaction before it can be executed. It uses the `secp256k1` elliptic curve cryptography library for signing and verification, which is the same cryptographic standard used in Bitcoin and Ethereum.

### Key Features

- **M-of-N Signature Scheme**: Configure a wallet requiring M signatures out of N total signers
- **Secp256k1 Cryptography**: Industry-standard elliptic curve cryptography for secure signing
- **Transaction Management**: Create, sign, and verify transactions with multiple signatures
- **Threshold Signature Support**: Only execute transactions when the required threshold is met
- **Robust Error Handling**: Comprehensive error types using `thiserror` for better debugging
- **Serialization Support**: JSON serialization for transactions and wallet state using `serde`

## Architecture

The project is structured into several core modules:

```
multisig-rs/
├── src/
│   ├── main.rs           # CLI entry point
│   ├── lib.rs            # Library root and module declarations
│   ├── wallet.rs         # MultisigWallet implementation
│   ├── transaction.rs    # Transaction structure and signing logic
│   ├── crypto.rs         # Cryptographic utilities (key generation, signing)
│   └── error.rs          # Custom error types
├── tests/
│   └── integration_tests.rs  # Integration tests
├── Cargo.toml            # Project dependencies
└── README.md             # This file
```

## How It Works

### 1. Wallet Creation
Create a multisig wallet by specifying:
- **N**: Total number of signers.
- **M**: Minimum number of signatures required (threshold).
- **Public Keys**: List of all authorized signers' public keys.

### 2. Transaction Proposal
Any authorized signer can propose a transaction containing:
- Recipient address.
- Amount to transfer.
- Optional metadata.

### 3. Signature Collection
Signers review and sign the proposed transaction:
- Each signature is verified against the authorized public keys.
- Signatures are collected until the threshold M is reached.

### 4. Transaction Execution
Once M valid signatures are collected:
- The transaction is verified
- If valid, the transaction can be executed.
- If invalid or insufficient signatures, the transaction is rejected.

## Cryptographic Primitives

### Secp256k1
- **Elliptic Curve**: secp256k1 (same as Bitcoin/Ethereum).
- **Key Generation**: Secure random private key generation.
- **Signing**: ECDSA (Elliptic Curve Digital Signature Algorithm).
- **Verification**: Public key recovery and signature validation.

### Hashing
- **SHA-256**: Used for transaction hashing before signing.
- Ensures data integrity and prevents tampering

## Use Cases

- **Corporate Treasury**: Require multiple executives to approve large transactions
- **DAO Governance**: Multi-party approval for fund disbursement
- **Escrow Services**: Buyer, seller, and arbiter must all agree
- **Security**: Reduce single point of failure by distributing signing authority

## Security Considerations

- **Private Key Management**: Private keys should never be shared or stored insecurely
- **Signature Verification**: All signatures are cryptographically verified before acceptance
- **Threshold Security**: Even if some keys are compromised, funds remain safe if below threshold
- **Replay Protection**: Each transaction should include unique identifiers to prevent replay attacks

## Getting Started

### Prerequisites
- Rust 1.70+ (install from [rustup.rs](https://rustup.rs/))
- Cargo (comes with Rust)

### Installation

```bash
git clone https://github.com/Cherrypick14/multisig-rs.git
cd multisig-rs
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Example Usage

```rust
use multisig_rs::{MultisigWallet, Transaction};

// Create a 2-of-3 multisig wallet
let wallet = MultisigWallet::new(2, vec![pubkey1, pubkey2, pubkey3]);

// Create a transaction
let tx = Transaction::new(recipient, amount);

// Sign with first key
let sig1 = tx.sign(&private_key1);
wallet.add_signature(&tx, sig1);

// Sign with second key (reaches threshold)
let sig2 = tx.sign(&private_key2);
wallet.add_signature(&tx, sig2);

// Verify and execute
if wallet.verify_transaction(&tx) {
    wallet.execute_transaction(&tx);
}
```

## Dependencies

- **secp256k1**: Elliptic curve cryptography
- **rand**: Secure random number generation
- **sha2**: SHA-256 hashing
- **serde**: Serialization/deserialization
- **serde_json**: JSON support
- **thiserror**: Error handling

## Roadmap

- [x] Project initialization
- [x] Core wallet implementation
- [x] Transaction signing and verification
- [ ] CLI interface
- [x] Comprehensive test suite
- [ ] Documentation and examples
- [ ] Advanced features (time locks, spending limits)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Bitcoin and Ethereum for secp256k1 standards
- Rust cryptography community
- Multi-signature wallet research and implementations

## Contact

For questions or suggestions, please open an issue on GitHub.
