use thiserror::Error;

#[derive(Error, Debug)]
pub enum RspassError {
    #[error("Encryption error")]
    EncryptionError(String),

    #[error("Hash error")]
    HashError(String),

    #[error("Invalid input")]
    InvalidInputError(String),

    #[error("Format error")]
    FormatError(String),

    #[error("IO error")]
    IOError(String),
}
