#![doc = include_str!("../../README.md")]

pub use {
    cose_key_confirmation::*,
    esdicawt_spec as spec,
    holder::{
        Holder,
        error::{SdCwtHolderError, SdCwtHolderResult},
        params::{CborPath, HolderParams, Presentation},
    },
    issuer::{
        Issuer,
        error::{SdCwtIssuerError, SdCwtIssuerResult},
        params::IssuerParams,
    },
    lookup::*,
    read::{EsdicawtReadError, EsdicawtReadResult, SdCwtRead},
    signature::Keypair,
    spec::reexports::*,
    spec::*,
    verifier::{
        Verifier,
        error::{SdCwtVerifierError, SdCwtVerifierResult},
        params::VerifierParams,
    },
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
