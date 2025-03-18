#![doc = include_str!("../../README.md")]

pub use cose_key_confirmation::{EncryptedCoseKey, KeyConfirmation, error::CoseKeyConfirmationError};
pub use esdicawt_spec as spec;
pub use holder::{
    Holder,
    error::{SdCwtHolderError, SdCwtHolderResult},
    params::{CwtPresentationParams, Presentation},
};
pub use issuer::{
    IssueCwtParams, Issuer,
    error::{SdCwtIssuerError, SdCwtIssuerResult},
};
pub use read::{EsdicawtReadError, EsdicawtReadResult, SdCwtRead};
pub use signature::Keypair;
pub use verifier::{
    Verifier, VerifyCwtParams,
    error::{SdCwtVerifierError, SdCwtVerifierResult},
};

mod holder;
mod issuer;
mod lookup;
mod read;
mod verifier;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::{holder::test_utils::*, issuer::test_utils::*};
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn now() -> u64 {
    let val = js_sys::Date::now();
    std::time::Duration::from_millis(val as u64).as_secs()
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn now() -> u64 {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::SystemTime::UNIX_EPOCH).expect("System clock is before UNIX_EPOCH").as_secs()
}
