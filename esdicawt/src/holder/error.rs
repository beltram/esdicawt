use esdicawt_spec::{EsdicawtSpecError, reexports::coset};

pub type SdCwtHolderResult<T, CustomError> = Result<T, SdCwtHolderError<CustomError>>;

#[derive(Debug, thiserror::Error)]
pub enum SdCwtHolderError<CustomError: Send + Sync> {
    #[error(transparent)]
    CoseError(#[from] coset::CoseError),
    #[error(transparent)]
    CborSerializeError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborDeserializeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[cfg(any(feature = "pem", feature = "der"))]
    #[error("{0}")]
    Pkcs8Error(pkcs8::Error),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error(transparent)]
    SpecError(#[from] EsdicawtSpecError),
    #[error("The issuer is not using an algorithm IANA registered")]
    UnregisteredAlgorithm,
    #[error("This hash algorithm is not supported")]
    UnsupportedHashAlgorithm,
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error(transparent)]
    CustomError(CustomError),
}

#[cfg(any(feature = "pem", feature = "der"))]
impl<T> From<pkcs8::Error> for SdCwtHolderError<T>
where
    T: core::error::Error + Send + Sync,
{
    fn from(err: pkcs8::Error) -> Self {
        Self::Pkcs8Error(err)
    }
}
