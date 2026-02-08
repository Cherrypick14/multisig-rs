use thiserror::Error;

/// Custom error types for the multisig wallet
#[derive(Error, Debug)]
pub enum MultisigError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Insufficient signatures: required {required}, got {actual}")]
    InsufficientSignatures { required: usize, actual: usize },

    #[error("Signer not authorized")]
    UnauthorizedSigner,

    #[error("Transaction already executed")]
    TransactionAlreadyExecuted,

    #[error("Invalid threshold: M={m} must be <= N={n}")]
    InvalidThreshold { m: usize, n: usize },

    #[error("Duplicate signature detected")]
    DuplicateSignature,

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid private key")]
    InvalidPrivateKey,

    #[error("Transaction not found")]
    TransactionNotFound,
}

pub type Result<T> = std::result::Result<T, MultisigError>;
