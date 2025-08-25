#[derive(Debug, thiserror::Error)]
pub enum CoseKeyError {
    #[cfg(feature = "p256")]
    #[error("Invalid P256 key")]
    InvalidP256Key,
    #[cfg(feature = "p384")]
    #[error("Invalid P384 key")]
    InvalidP384Key,
    #[error("Invalid KeyType")]
    InvalidKty,
    #[error("Unknown algorithm '{0:?}'. Algorithms need to be IANA assigned")]
    UnknownAlg(coset::Algorithm),
    #[error("A COSE key must have an algorithm")]
    MissingAlg,
    #[error("Unknown elliptic curve '{0}'")]
    UnknownCurve(i64),
    #[error("Expected the KeyConfirmation to be of type '{0}' but was '{1}'")]
    InvalidAlg(i64, i64),
    #[error("Missing 'crv' claim")]
    MissingCrv,
    #[error("Missing EC point '{0}'")]
    MissingPoint(&'static str),
    #[error("Invalid key length ; expected '{0}' got '{1}'")]
    InvalidKeyLength(usize, usize),
    #[error("{0}")]
    InvalidCborIntegerClaimKey(core::num::TryFromIntError),
    #[error(transparent)]
    CborDeserializationError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborSerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[cfg(feature = "pem")]
    #[error(transparent)]
    Pkcs8Error(#[from] pkcs8::spki::Error),
    #[error("Signature error {0}")]
    SignatureError(String),
    #[error(transparent)]
    InfallibleError(#[from] core::convert::Infallible),
}

#[cfg(feature = "ed25519")]
impl From<ed25519_dalek::SignatureError> for CoseKeyError {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Self::SignatureError(format!("{e:?}"))
    }
}
