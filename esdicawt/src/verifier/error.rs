use crate::{signature_verifier::SignatureVerifierError, time::CwtTimeError};

pub type SdCwtVerifierResult<T, CustomError> = Result<T, SdCwtVerifierError<CustomError>>;

#[derive(Debug, thiserror::Error)]
pub enum SdCwtVerifierError<CustomError: Send + Sync> {
    #[error("Expected sub to be '{expected}' but was '{actual}'")]
    SubMismatch { expected: String, actual: String },
    #[error("Expected issuer to be '{expected}' but was '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
    #[error("Expected audience to be '{expected}' but was '{actual}'")]
    AudienceMismatch { expected: String, actual: String },
    #[error("Expected SD-KBT audience to be '{expected}' but was '{actual}'")]
    KbtAudienceMismatch { expected: String, actual: String },
    #[error("Expected cnonce to be '{expected:x?}' but was '{actual:x?}'")]
    CnonceMismatch { expected: Vec<u8>, actual: Vec<u8> },
    #[error("Signature encoding error")]
    SignatureEncodingError,
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
    #[error("Invalid SD-CWT")]
    InvalidSdCwt,
    #[error("Invalid SD-KBT")]
    InvalidSdKbt,
    #[error("This algorithm is not supported")]
    UnsupportedAlgorithm,
    #[error(transparent)]
    KeyConfirmationError(#[from] cose_key_confirmation::error::CoseKeyConfirmationError),
    #[error(transparent)]
    IssuerSignatureValidationError(#[from] SignatureVerifierError),
    #[error(transparent)]
    TimeError(#[from] CwtTimeError),
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
