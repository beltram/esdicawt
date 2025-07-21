#![doc = include_str!("../../README.md")]

pub use cose_key;
pub use cose_key_confirmation;
pub use cose_key_set;
pub use esdicawt_spec as spec;
pub use esdicawt_spec::reexports::coset;
pub use holder::{
    Holder, SdCwtVerified,
    error::{SdCwtHolderError, SdCwtHolderResult},
    params::{CborPath, HolderParams, Presentation},
    validation::{HolderValidationParams, SdCwtHolderValidationError},
};
#[cfg(feature = "status")]
pub use issuer::params::RevocationParams;
pub use issuer::{
    Issuer,
    error::{SdCwtIssuerError, SdCwtIssuerResult},
    params::IssuerParams,
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
pub(crate) mod time;
mod verifier;

#[cfg(feature = "test-utils")]
pub mod test_utils {
    pub use crate::{holder::test_utils::*, issuer::test_utils::*};
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
    now.duration_since(std::time::SystemTime::UNIX_EPOCH).expect("System clock is before UNIX_EPOCH")
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

        impl From<$label> for esdicawt::spec::ClaimName {
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
