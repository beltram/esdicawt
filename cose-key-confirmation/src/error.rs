#[derive(Debug, thiserror::Error)]
pub enum CoseKeyConfirmationError {
    #[error("Tried to compute a verifying key out of a KeyConfirmation that was not a CoseKey")]
    NotCoseKey,
    #[error(transparent)]
    CoseKeyError(#[from] cose_key::CoseKeyError),
    #[cfg(feature = "thumbprint")]
    #[error(transparent)]
    CoseKeyThumbprintError(#[from] cose_key_thumbprint::CoseKeyThumbprintError),
    #[error(transparent)]
    UnknownError(#[from] core::convert::Infallible),
}
