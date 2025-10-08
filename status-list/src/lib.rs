mod error;
mod inner;
mod lst;
mod referenced;
mod statuses;
mod twiddling;

#[cfg(feature = "issuer")]
pub mod issuer;

use ciborium::Value;
use serde::ser::SerializeMap;
use std::hash::Hash;

pub use {
    error::{StatusListError, StatusListResult},
    lst::Lst,
    referenced::{StatusClaim, StatusListClaim},
    statuses::{OauthStatus, RawStatus},
};

pub type BitIndex = u64;

pub trait Status: From<u8> + Into<u8> + Clone + Eq + PartialEq + Hash {
    const BITS: StatusBits;

    fn is_valid(&self) -> bool;
}

/// Marker for statuses with a state representing that they have not yet been assigned a value
pub trait StatusUndefined {
    fn is_undefined(&self) -> bool;
}

/// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-11#section-4.3
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct StatusList<S: Status = u8> {
    /// Byte string (Major Type 2) that contains the status values for all the Referenced Tokens it conveys statuses for. The value MUST be the compressed byte array.
    lst: Lst<S>,
    /// Text string (Major Type 3) that contains a URI to retrieve the Status List Aggregation for this type of Referenced Token
    aggregation_uri: Option<url::Url>,
}

impl<S: Status> StatusList<S> {
    /// Create a new StatusList.
    /// Arguments:
    /// * nb_statuses: number of statuses this list should hold
    pub fn new(nb_statuses: usize, aggregation_uri: Option<url::Url>) -> Self {
        Self {
            lst: Lst::new(nb_statuses),
            aggregation_uri,
        }
    }

    /// Create a new StatusList.
    /// It is RECOMMENDED that the size of a Status List in bits is divisible in bytes (8 bits) without a remainder.
    /// Arguments:
    /// * capacity: in bits
    pub fn with_capacity(bit_capacity: usize, aggregation_uri: Option<url::Url>) -> Self {
        Self {
            lst: Lst::with_capacity(bit_capacity),
            aggregation_uri,
        }
    }

    pub fn from_slice(bits: &[u8], aggregation_uri: Option<url::Url>) -> Self {
        Self {
            lst: Lst::from_slice(bits),
            aggregation_uri,
        }
    }

    pub fn from_vec(bits: Vec<u8>, aggregation_uri: Option<url::Url>) -> Self {
        Self {
            lst: Lst::from_vec(bits),
            aggregation_uri,
        }
    }

    /// Builds a new StatusList from an existing immutable list
    pub fn from_lst(lst: Lst<S>, aggregation_uri: Option<url::Url>) -> Self {
        Self { lst, aggregation_uri }
    }

    /// Builds a new StatusList from an existing mutable list
    #[cfg(feature = "issuer")]
    pub fn from_lst_mut(lst: issuer::LstMut<S>, aggregation_uri: Option<url::Url>) -> Self {
        Self { lst: lst.into(), aggregation_uri }
    }

    /// Flips a status.
    /// Note: will only copy the underlying bytes if there is another StatusList with the same content ; this
    /// should rarely happen with large enough lists (except at initialization which is expected).
    #[cfg(feature = "issuer")]
    pub fn set(&mut self, index: BitIndex, new: impl Into<S>) -> Option<S> {
        let mut lst_mut = issuer::LstMut::from(self.lst.clone());
        let old_status = lst_mut.set(index, new);
        self.lst = lst_mut.into();
        old_status
    }

    /// Read a status from the list as bit.
    /// Might panic in case of overflow, prefer [Self::get_raw]
    pub fn get_raw_unchecked(&self, index: BitIndex) -> S {
        self.lst.get_raw_unchecked(index)
    }

    /// Read a status from the list as bit
    pub fn get_raw(&self, index: BitIndex) -> Option<S> {
        self.lst.get_raw(index)
    }

    pub fn lst(&self) -> &Lst<S> {
        &self.lst
    }

    pub fn max_index(&self) -> BitIndex {
        self.lst.max_index()
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

                Ok(Self::Value::from_lst(lst, aggregation_uri))
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
        let status_list = StatusList::<RawStatus<1>>::from_slice(&[0xB9, 0xA3], None);
        let expected = "a2646269747301636c73744a78dadbb918000217015d";
        let actual = status_list.to_cbor_bytes().unwrap().encode_hex::<String>();

        assert_eq!(actual, expected);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn ser_de() {
        let input = StatusList::<RawStatus<1>>::from_slice(&[0xB9, 0xA3], Some("https://agg.com".parse().unwrap()));
        let ser = input.to_cbor_bytes().unwrap();
        let output = StatusList::from_cbor_bytes(&ser).unwrap();
        assert_eq!(input, output);
    }
}
