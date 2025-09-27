#![doc = include_str!("../../README.md")]

pub use {
    cose_key_confirmation::{error::CoseKeyConfirmationError, EncryptedCoseKey, KeyConfirmation},
    esdicawt_spec as spec,
    holder::{
        error::{SdCwtHolderError, SdCwtHolderResult},
        params::{CwtPresentationParams, Presentation},
        Holder,
    },
    issuer::{
        error::{SdCwtIssuerError, SdCwtIssuerResult},
        IssueCwtParams, Issuer,
    },
    read::{EsdicawtReadError, EsdicawtReadResult, SdCwtRead},
    signature::Keypair,
    verifier::{
        error::{SdCwtVerifierError, SdCwtVerifierResult},
        Verifier, VerifyCwtParams,
    },
};

mod holder;
mod issuer;
mod read;
mod verifier;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::holder::test_utils::*;
    pub use crate::issuer::test_utils::*;
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
