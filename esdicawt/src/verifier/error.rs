#[derive(Debug, thiserror::Error)]
pub enum SdCwtVerifierError<CustomError: Send + Sync> {
    #[error("Signature verification error: {0}")]
    SignatureError(#[from] signature::Error),
    #[error(transparent)]
    CborSerializeError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborDeserializeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    CoseError(#[from] esdicawt_spec::reexports::coset::CoseError),
    #[error(transparent)]
    SpecError(#[from] esdicawt_spec::EsdicawtSpecError),
    #[error(transparent)]
    KeyConfirmationError(#[from] cose_key_confirmation::error::CoseKeyConfirmationError),
    #[error("The type of Key Confirmation in the SD-CWT is not supported")]
    UnsupportedKeyConfirmation,
    #[error("The Key Confirmation in the SD-KBT is not the expected one")]
    UnexpectedKeyConfirmation,
    #[error("Disclosure hash collision")]
    DisclosureHashCollision,
    #[error("CWT 'iat' is in the future")]
    ClockDrift,
    #[error("CWT not valid yet")]
    NotValidYet,
    #[error("CWT expired")]
    Expired,
    #[error("Malformed SD-CWT because {0}")]
    MalformedSdCwt(&'static str),
    #[error(transparent)]
    CustomError(CustomError),
}

pub type SdCwtVerifierResult<T, CustomError> = Result<T, SdCwtVerifierError<CustomError>>;
