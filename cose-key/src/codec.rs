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

pub mod deterministic_encoding {
    use crate::utils::CwtAny;
    use ciborium::Value;

    pub trait CborDeterministicEncoded {
        // Given ciborium reordering of Map entries we have to resort to this crime
        fn deterministically_serialize_map(&self) -> Result<Vec<u8>, DeterministicEncodingError>;
    }

    impl CborDeterministicEncoded for Value {
        fn deterministically_serialize_map(&self) -> Result<Vec<u8>, DeterministicEncodingError> {
            let mut buf = vec![];
            match self.as_map() {
                Some(v) => {
                    let size = v.len();

                    let map = Self::Map(vec![(Self::Null, Self::Null); size]);
                    let ser = map.to_cbor_bytes()?;

                    // SAFETY: serializing even an empty map yields at least one byte
                    // trims the major type
                    let first_byte = ser.first().ok_or(DeterministicEncodingError::InvalidCborError)?;
                    let prelude = first_byte >> 3;

                    let map_prelude = match prelude {
                        ..=23 => [*first_byte].to_vec(),
                        24 => ser.get(0..2).ok_or(DeterministicEncodingError::InvalidCborError)?.to_vec(),
                        25 => ser.get(0..3).ok_or(DeterministicEncodingError::InvalidCborError)?.to_vec(),
                        26 => ser.get(0..5).ok_or(DeterministicEncodingError::InvalidCborError)?.to_vec(),
                        27 => ser.get(0..9).ok_or(DeterministicEncodingError::InvalidCborError)?.to_vec(),
                        _ => return Err(DeterministicEncodingError::InvalidCborError),
                    };

                    buf.extend_from_slice(&map_prelude[..]);

                    let mut v = v
                        .iter()
                        .map(|(k, v)| {
                            let mut e = vec![];
                            ciborium::into_writer(k, &mut e)?;
                            ciborium::into_writer(v, &mut e)?;
                            Ok::<_, DeterministicEncodingError>(e)
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    // sort in lexicographic order on the bytes
                    v.sort();

                    // append the map entries to the existing buffer with the CBOR Map prelude
                    for e in v {
                        buf.extend_from_slice(&e);
                    }
                }
                _ => {
                    // else default to ciborium so it might not be deterministically encoded
                    // we use this method primarily for Cose KeyThumbprint so only Map is required here
                    self.to_cbor_bytes()?;
                }
            }
            Ok(buf)
        }
    }

    #[derive(Debug, thiserror::Error)]
    pub enum DeterministicEncodingError {
        #[error(transparent)]
        CborSerializeError(#[from] ciborium::ser::Error<std::io::Error>),
        #[error("{0}")]
        DCborError(String),
        #[error("Invalid CBOR")]
        InvalidCborError,
    }
}
