mod error;
mod inner;
mod lst;
pub mod referenced;
mod twiddling;

#[cfg(feature = "issuer")]
pub mod issuer;

use ciborium::Value;
use serde::ser::SerializeMap;
use std::hash::Hash;

pub use error::{StatusListError, StatusListResult};
pub use lst::Lst;

pub type BitIndex = u64;

pub trait Status: From<u8> + Into<u8> + Clone + Eq + PartialEq + Hash {
    const BITS: StatusBits;
}

/// Marker for statuses with a state representing that they have not yet been assigned a value
pub trait StatusUndefined {
    fn is_undefined(&self) -> bool;
}

/// Just an u8 with the right bounds for representing a Status
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct RawStatus<const B: usize>(pub u8);

impl<const B: usize> Status for RawStatus<B> {
    const BITS: StatusBits = StatusBits::from_raw(B);
}
impl<const B: usize> From<RawStatus<B>> for u8 {
    fn from(s: RawStatus<B>) -> Self {
        s.0
    }
}
impl<const B: usize> From<u8> for RawStatus<B> {
    fn from(s: u8) -> Self {
        Self(s)
    }
}

/// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.3
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct StatusList<S: Status> {
    /// Byte string (Major Type 2) that contains the status values for all the Referenced Tokens it conveys statuses for. The value MUST be the compressed byte array.
    lst: Lst<S>,
    /// Text string (Major Type 3) that contains a URI to retrieve the Status List Aggregation for this type of Referenced Token
    aggregation_uri: Option<url::Url>,
}

impl<S: Status> StatusList<S> {
    /// Builds a new StatusList from an existing immutable list
    pub fn new(lst: Lst<S>, aggregation_uri: Option<url::Url>) -> Self {
        Self { lst, aggregation_uri }
    }
}

impl<St: Status> serde::Serialize for StatusList<St> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let size = 2 + self.aggregation_uri.as_ref().map(|_| 1).unwrap_or_default();
        let mut map = serializer.serialize_map(Some(size))?;
        map.serialize_entry("bits", &St::BITS)?;
        let lst = self.lst.status_list_compressed().map_err(serde::ser::Error::custom)?;
        let lst = serde_bytes::ByteBuf::from(lst);
        map.serialize_entry("lst", &lst)?;
        if let Some(aggregation_uri) = &self.aggregation_uri {
            map.serialize_entry("aggregation_uri", aggregation_uri)?;
        }
        map.end()
    }
}

impl<'de, S: Status> serde::Deserialize<'de> for StatusList<S> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StatusListVisitor<St: Status>(core::marker::PhantomData<St>);

        impl<'de, S: Status> serde::de::Visitor<'de> for StatusListVisitor<S> {
            type Value = StatusList<S>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a StatusList")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let (mut bits, mut lst, mut aggregation_uri) = (None, None, None);
                while let Some(k) = map.next_key::<String>()? {
                    match k.as_str() {
                        "bits" => {
                            bits.replace(map.next_value::<StatusBits>()?);
                        }
                        "lst" => {
                            let lst_bytes = map.next_value::<bytes::Bytes>()?;
                            let lst_bytes = Lst::<S>::from_compressed(lst_bytes.as_ref()).map_err(A::Error::custom)?;
                            lst.replace(bytes::Bytes::from(lst_bytes));
                        }
                        "aggregation_uri" => {
                            aggregation_uri.replace(map.next_value::<url::Url>()?);
                        }
                        _ => return Err(serde::de::Error::custom("Unsupported claim in a StatusList")),
                    };
                }

                let bits = bits.ok_or_else(|| serde::de::Error::custom("bits required in a StatusList"))?;
                if bits != S::BITS {
                    return Err(A::Error::custom("Advertised StatusBits do not match the expected ones"));
                }

                let lst = lst
                    .map(|lst| Lst::<S>(lst, Default::default()))
                    .ok_or_else(|| serde::de::Error::custom("lst required in a StatusList"))?;

                Ok(Self::Value::new(lst, aggregation_uri))
            }
        }

        deserializer.deserialize_map(StatusListVisitor::<S>(Default::default()))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(u8)]
pub enum StatusBits {
    One = 1,
    Two = 2,
    Four = 4,
    Eight = 8,
}

impl StatusBits {
    pub const fn from_raw(b: usize) -> Self {
        match b {
            1 => Self::One,
            2 => Self::Two,
            4 => Self::Four,
            8 => Self::Eight,
            _ => unreachable!(),
        }
    }

    #[inline(always)]
    pub const fn size(&self) -> u8 {
        *self as u8
    }

    #[inline(always)]
    pub const fn mask(&self) -> u8 {
        // Given status bits:
        // - 1 -> 0b0000_0001
        // - 2 -> 0b0000_0011
        // - 4 -> 0b0000_1111
        // - 8 -> 0b1111_1111
        !(u8::MAX.wrapping_shl(self.size() as u32))
    }

    #[inline(always)]
    pub const fn max_bit_index(&self) -> u8 {
        match self {
            Self::One => 7,
            Self::Two => 3,
            Self::Four => 1,
            Self::Eight => 0,
        }
    }
}

pub(crate) trait CborAny: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone {
    #[allow(dead_code)]
    fn to_cbor_bytes(&self) -> StatusListResult<Vec<u8>> {
        let mut buf = vec![];
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    #[allow(dead_code)]
    fn from_cbor_bytes(bytes: &[u8]) -> StatusListResult<Self>
    where
        Self: Sized,
    {
        Ok(ciborium::from_reader(bytes)?)
    }

    #[allow(dead_code)]
    fn to_cbor_value(&self) -> StatusListResult<Value> {
        Ok(Value::serialized(self)?)
    }

    #[allow(dead_code)]
    fn from_cbor_value(value: &Value) -> StatusListResult<Self> {
        Ok(value.deserialized::<Self>()?)
    }
}

impl<T> CborAny for T where T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone {}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn cbor_example() {
        let status_list = StatusList::<RawStatus<1>>::new(Lst::from_slice(&[0xB9, 0xA3]), None);
        let expected = "a2646269747301636c73744a78dadbb918000217015d";
        let actual = status_list.to_cbor_bytes().unwrap().encode_hex::<String>();

        assert_eq!(actual, expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn ser_de() {
        let input = StatusList::<RawStatus<1>>::new(Lst::from_slice(&[0xB9, 0xA3]), Some("https://agg.com".parse().unwrap()));
        let ser = input.to_cbor_bytes().unwrap();
        let output = StatusList::from_cbor_bytes(&ser).unwrap();
        assert_eq!(input, output);
    }
}
