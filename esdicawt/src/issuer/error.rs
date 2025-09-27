use ciborium::Value;
use esdicawt_spec::{EsdicawtSpecError, reexports::coset};

pub type SdCwtIssuerResult<T, CustomError> = Result<T, SdCwtIssuerError<CustomError>>;

#[derive(Debug, thiserror::Error)]
pub enum SdCwtIssuerError<CustomError: Send + Sync> {
    #[error(transparent)]
    SpecError(#[from] EsdicawtSpecError),
    #[error(transparent)]
    CoseError(#[from] coset::CoseError),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error(transparent)]
    CborSerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborDeserializationError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    RngError(#[from] rand_core::Error),
    #[error("{0}")]
    CwtError(&'static str),
    #[error("Should have been a mapping")]
    InputError,
    #[error(transparent)]
    CborIntegerError(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    CustomError(CustomError),
}

impl<CustomError: Send + Sync> From<Value> for SdCwtIssuerError<CustomError> {
    fn from(_: Value) -> Self {
        Self::InputError
    }
}
