// #![doc = include_str!("../../README.md")] // FIXME: including this currently fails when this crate is transitively used by another crate built with Bazel

#[cfg(feature = "status")]
pub use {
    issuer::params::StatusParams,
    verifier::{VerifiedStatusListToken, VerifierWithStatus, error::SdCwtStatusVerifierError, params::StatusListVerifierParams},
};

pub use crate::spec::reexports::coset;
pub use cose_key;
pub use esdicawt_spec as spec;
pub use holder::{
    Holder, SdCwtVerified,
    accessor::ClaimSetExt,
    error::{SdCwtHolderError, SdCwtHolderResult},
    params::{CborPath, HolderParams, KbtIatOrCti, Presentation},
    validation::{HolderValidationParams, SdCwtHolderValidationError},
};
pub use issuer::{
    Issuer,
    error::{SdCwtIssuerError, SdCwtIssuerResult},
    params::{IssuerParams, Subject},
};
pub use lookup::*;
pub use read::{EsdicawtReadError, EsdicawtReadResult, SdCwtRead};
pub use signature::Keypair;
pub use time::{CwtTimeError, TimeArg, TimeVerification};
pub use verifier::{
    Verifier,
    error::{SdCwtVerifierError, SdCwtVerifierResult},
    params::{ShallowVerifierParams, VerifierParams},
};

pub(crate) mod any_digest;
mod holder;
mod issuer;
mod lookup;
mod read;
mod signature_verifier;
#[cfg(test)]
pub mod snapshots;
pub(crate) mod time;
mod verifier;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::{holder::test_utils::*, issuer::test_utils::*};
}

/// Hasher of the Salted Disclosed Claims for the 'sd_alg' of an SD-CWT, among the ones enabled by the features
#[cfg(any(feature = "ed25519", feature = "p256", feature = "p384"))]
pub(crate) fn default_digest(sd_hash_alg: spec::SdHashAlg) -> Option<std::rc::Rc<dyn digest::DynDigest>> {
    match sd_hash_alg {
        #[cfg(any(feature = "ed25519", feature = "p256"))]
        spec::SdHashAlg::Sha256 => Some(std::rc::Rc::new(sha2::Sha256::default())),
        #[cfg(feature = "p384")]
        spec::SdHashAlg::Sha384 => Some(std::rc::Rc::new(sha2::Sha384::default())),
        _ => None,
    }
}

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub(crate) fn elapsed_since_epoch() -> core::time::Duration {
    let js_date = js_sys::Date::new_0();
    let timestamp_millis = js_date.get_time() as u64;
    std::time::Duration::from_millis(timestamp_millis)
}

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub(crate) fn elapsed_since_epoch() -> core::time::Duration {
    let now = std::time::SystemTime::now();
    // a clock before UNIX_EPOCH is broken, the UNIX_EPOCH itself makes every time verification fail instead of panicking
    now.duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap_or_default()
}

/// Helps managing CBOR integer labels declared in an enum.
/// Could have been a proc macro (but laziness stroke)
#[macro_export]
macro_rules! cwt_label {
    ($label:ty) => {
        impl PartialEq<ciborium::value::Integer> for $label {
            fn eq(&self, other: &ciborium::value::Integer) -> bool {
                ciborium::value::Integer::from(*self as i64).eq(other)
            }
        }

        impl PartialEq<$label> for ciborium::value::Integer {
            fn eq(&self, other: &$label) -> bool {
                ciborium::value::Integer::from(*other as i64).eq(self)
            }
        }

        impl PartialEq<i64> for $label {
            fn eq(&self, other: &i64) -> bool {
                (*self as i64).eq(other)
            }
        }

        impl PartialEq<$label> for i64 {
            fn eq(&self, other: &$label) -> bool {
                (*other as i64).eq(self)
            }
        }

        impl From<$label> for esdicawt::spec::SdCwtClaim {
            fn from(label: $label) -> Self {
                (label as i64).into()
            }
        }

        impl From<$label> for esdicawt::QueryElement {
            fn from(label: $label) -> Self {
                (label as i64).into()
            }
        }

        impl From<$label> for ciborium::Value {
            fn from(label: $label) -> Self {
                (label as i64).into()
            }
        }
    };
}

use crate as esdicawt;

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, enum_variants_strings::EnumVariantsStrings)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum CwtStdLabel {
    Issuer = coset::iana::CwtClaimName::Iss as i64,
    Subject = coset::iana::CwtClaimName::Sub as i64,
    Audience = coset::iana::CwtClaimName::Aud as i64,
    ExpiresAt = coset::iana::CwtClaimName::Exp as i64,
    NotBefore = coset::iana::CwtClaimName::Nbf as i64,
    IssuedAt = coset::iana::CwtClaimName::Iat as i64,
    Cnonce = coset::iana::CwtClaimName::CNonce as i64,
    Cti = coset::iana::CwtClaimName::Cti as i64,
    KeyConfirmation = coset::iana::CwtClaimName::Cnf as i64,
    Status = coset::iana::CwtClaimName::Status as i64,
}
cwt_label!(CwtStdLabel);
