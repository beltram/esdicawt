use ciborium::Value;
use esdicawt_spec::SdCwtClaim;
use serde::ser::SerializeTuple;

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
pub struct Query(pub Vec<QueryElement>);

impl std::ops::Deref for Query {
    type Target = [QueryElement];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for Query {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<Vec<QueryElement>> for Query {
    fn from(elements: Vec<QueryElement>) -> Self {
        Self(elements)
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
/// enum for claim queries, allowing for future ways to query the token
// TODO: this should go away and use cbor pointer
pub enum QueryElement {
    /// selects a claim key
    ClaimName(SdCwtClaim),
    /// Selects an element in an array
    Index(usize),
    /// Selects all the elements within an array
    Wildcard,
}

impl serde::Serialize for QueryElement {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(2)?;
        match self {
            Self::ClaimName(name) => {
                tuple.serialize_element(&0u8)?;
                tuple.serialize_element(name)?;
            }
            Self::Index(idx) => {
                tuple.serialize_element(&1u8)?;
                tuple.serialize_element(idx)?;
            }
            Self::Wildcard => {
                tuple.serialize_element(&2u8)?;
            }
        }
        tuple.end()
    }
}

impl<'de> serde::Deserialize<'de> for QueryElement {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let (key, value) = <(u8, Value) as serde::Deserialize>::deserialize(deserializer)?;
        match key {
            0 => Ok(Self::ClaimName(value.deserialized().map_err(D::Error::custom)?)),
            1 => Ok(Self::Index(value.deserialized().map_err(D::Error::custom)?)),
            _ => Err(serde::de::Error::custom("Unknown QueryElement variant")),
        }
    }
}

impl From<&str> for QueryElement {
    fn from(s: &str) -> Self {
        Self::ClaimName(s.into())
    }
}

impl From<i64> for QueryElement {
    fn from(i: i64) -> Self {
        Self::ClaimName(i.into())
    }
}

impl From<usize> for QueryElement {
    fn from(i: usize) -> Self {
        Self::Index(i)
    }
}
