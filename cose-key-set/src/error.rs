#[derive(Debug, thiserror::Error)]
pub enum CoseKeySetError {
    #[error(transparent)]
    CoseKeyError(#[from] cose_key::CoseKeyError),
    #[error(transparent)]
    UnknownError(#[from] core::convert::Infallible),
}
