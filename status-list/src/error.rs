pub type StatusListResult<T> = Result<T, StatusListError>;

#[derive(Debug, thiserror::Error)]
pub enum StatusListError {
    #[error(transparent)]
    CborDeserializationError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborSerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error("{0}")]
    CoseError(String),
    #[error(transparent)]
    IoError(#[from] std::io::Error),
}

impl From<coset::CoseError> for StatusListError {
    fn from(err: coset::CoseError) -> Self {
        Self::CoseError(err.to_string())
    }
}
