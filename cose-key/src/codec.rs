//! Serialization.
//! Given ciborium does not implement deterministic encoding as defined in https://datatracker.ietf.org/doc/html/rfc8949#section-4.2
//!

use crate::CoseKey;
use coset::AsCborValue as _;
use serde::{Deserializer, Serializer};

impl serde::Serialize for CoseKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let value = self.0.clone().to_cbor_value().map_err(S::Error::custom)?;
        value.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for CoseKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = <ciborium::Value as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Self(coset::CoseKey::from_cbor_value(value).map_err(D::Error::custom)?))
    }
}

#[cfg(feature = "deterministic-encoding")]
pub mod deterministic_encoding {
    pub trait CborDeterministicEncoded {
        fn deterministically_serialize(&self) -> Result<Vec<u8>, DeterministicEncodingError>;
    }

    impl CborDeterministicEncoded for ciborium::Value {
        fn deterministically_serialize(&self) -> Result<Vec<u8>, DeterministicEncodingError> {
            let mut raw = vec![];
            ciborium::into_writer(self, &mut raw)?;

            Ok(dcbor::CBOR::try_from_data(&raw[..])
                .map_err(|e| DeterministicEncodingError::DCborError(format!("{e:?}")))?
                .to_cbor_data())
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DeterministicEncodingError {
        #[error(transparent)]
        CborSerializeError(#[from] ciborium::ser::Error<std::io::Error>),
        #[error("{0}")]
        DCborError(String),
    }
}
