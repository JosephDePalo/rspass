use thiserror::Error;

#[derive(Error, Debug)]
pub enum RspassError {
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Hash error: {0}")]
    HashError(String),

    #[error("Invalid input: {0}")]
    InvalidInputError(String),

    #[error("Format error: {0}")]
    FormatError(String),

    #[error("IO error: {0}")]
    IOError(String),
}
