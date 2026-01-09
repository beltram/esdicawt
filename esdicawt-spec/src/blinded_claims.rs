use super::{CwtAny, Salt, SdCwtClaim};
use crate::{EsdicawtSpecResult, inlined_cbor::InlinedCbor};
use ciborium::Value;
use serde::ser::SerializeSeq;
use std::{borrow::Cow, collections::HashMap};

#[derive(Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedElement<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
}

impl<T: CwtAny> std::fmt::Debug for SaltedElement<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(value) = self.value.to_cbor_value() {
            write!(f, "{value:?}")
        } else {
            write!(f, "???")
        }
    }
}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple)]
pub struct SaltedElementRef<'a, T: CwtAny> {
    pub salt: Salt,
    pub value: &'a T,
}

// Do not change the order of the claims !!!
#[derive(Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedClaim<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
    pub name: SdCwtClaim,
}

impl<T: CwtAny> std::fmt::Debug for SaltedClaim<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(value) = self.value.to_cbor_value() {
            write!(f, "{:?}: {value:?} ({:?})", self.name, self.salt)
        } else {
            write!(f, "{:?}: ??? ({:?})", self.name, self.salt)
        }
    }
}

// Do not change the order of the claims !!!
#[derive(Debug, Clone, serde_tuple::Serialize_tuple)]
pub struct SaltedClaimRef<'a, T: CwtAny> {
    pub salt: Salt,
    pub value: &'a T,
    pub name: &'a SdCwtClaim,
}

#[derive(Debug, Clone, Copy, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct Decoy {
    pub salt: (Salt,),
}

impl PartialEq for Decoy {
    fn eq(&self, other: &Self) -> bool {
        self.salt.0.eq(&other.salt.0)
    }
}

impl Eq for Decoy {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Salted<T: CwtAny> {
    Claim(SaltedClaim<T>),
    Element(SaltedElement<T>),
    Decoy(Decoy),
}

impl<T: CwtAny> Salted<T> {
    pub fn upcast(self) -> EsdicawtSpecResult<Salted<Value>> {
        Ok(match self {
            Self::Claim(SaltedClaim { salt, value, name }) => Salted::<Value>::Claim(SaltedClaim {
                salt,
                value: value.to_cbor_value()?,
                name,
            }),
            Self::Element(SaltedElement { salt, value }) => Salted::<Value>::Element(SaltedElement {
                salt,
                value: value.to_cbor_value()?,
            }),
            Self::Decoy(salt) => Salted::<Value>::Decoy(salt),
        })
    }

    pub fn salt(&self) -> Salt {
        match self {
            Self::Claim(SaltedClaim { salt, .. }) | Self::Element(SaltedElement { salt, .. }) => *salt,
            Self::Decoy(Decoy { salt: (s, ..) }) => *s,
        }
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Claim(SaltedClaim { value, .. }) | Self::Element(SaltedElement { value, .. }) => Some(value),
            Self::Decoy(_) => None,
        }
    }

    pub fn name(&self) -> Option<&SdCwtClaim> {
        match self {
            Self::Claim(SaltedClaim { name, .. }) => Some(name),
            _ => None,
        }
    }
}

impl<T: CwtAny> serde::Serialize for Salted<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Claim(SaltedClaim { salt, name, value }) => {
                let mut array = serializer.serialize_seq(Some(3))?;
                array.serialize_element(salt)?;
                array.serialize_element(value)?;
                array.serialize_element(name)?;
                array.end()
            }
            Self::Element(SaltedElement { salt, value }) => {
                let mut array = serializer.serialize_seq(Some(2))?;
                array.serialize_element(salt)?;
                array.serialize_element(value)?;
                array.end()
            }
            Self::Decoy(Decoy { salt: (salt,) }) => {
                let mut array = serializer.serialize_seq(Some(1))?;
                array.serialize_element(salt)?;
                array.end()
            }
        }
    }
}

impl<'de, T: CwtAny> serde::Deserialize<'de> for Salted<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SaltedVisitor<T: CwtAny>(core::marker::PhantomData<T>);

        impl<'de, T: CwtAny> serde::de::Visitor<'de> for SaltedVisitor<T> {
            type Value = Salted<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a salted disclosure")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let salt = seq.next_element::<Salt>()?.ok_or_else(|| A::Error::custom("Missing salt in salted"))?;
                let value = seq.next_element::<T>()?;
                let name = seq.next_element::<SdCwtClaim>()?;

                Ok(match (salt, value, name) {
                    (salt, None, None) => Salted::Decoy(Decoy { salt: (salt,) }),
                    (salt, Some(value), None) => Salted::Element(SaltedElement { salt, value }),
                    (salt, Some(value), Some(name)) => Salted::Claim(SaltedClaim { salt, value, name }),
                    _ => return Err(A::Error::custom("Invalid disclosure")),
                })
            }
        }

        deserializer.deserialize_seq(SaltedVisitor(Default::default()))
    }
}

impl<T: CwtAny> From<SaltedClaim<T>> for Salted<T> {
    fn from(v: SaltedClaim<T>) -> Self {
        Self::Claim(v)
    }
}

impl<T: CwtAny> From<SaltedElement<T>> for Salted<T> {
    fn from(v: SaltedElement<T>) -> Self {
        Self::Element(v)
    }
}

impl<T: CwtAny> From<Decoy> for Salted<T> {
    fn from(v: Decoy) -> Self {
        Self::Decoy(v)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged, bound = "T: CwtAny")]
pub enum SaltedRef<'a, T: CwtAny> {
    Claim(SaltedClaimRef<'a, T>),
    Element(SaltedElementRef<'a, T>),
    Decoy(Decoy),
}

impl<'a, T: CwtAny> From<SaltedClaimRef<'a, T>> for SaltedRef<'a, T> {
    fn from(v: SaltedClaimRef<'a, T>) -> Self {
        Self::Claim(v)
    }
}

impl<'a, T: CwtAny> From<SaltedElementRef<'a, T>> for SaltedRef<'a, T> {
    fn from(v: SaltedElementRef<'a, T>) -> Self {
        Self::Element(v)
    }
}

impl<T: CwtAny> From<Decoy> for SaltedRef<'_, T> {
    fn from(v: Decoy) -> Self {
        Self::Decoy(v)
    }
}

impl<'a, T: CwtAny> From<SaltedRef<'a, T>> for Salted<T> {
    fn from(s: SaltedRef<'a, T>) -> Self {
        match s {
            SaltedRef::Claim(SaltedClaimRef { salt, value, name }) => Self::Claim(SaltedClaim {
                salt,
                value: value.to_owned(),
                name: name.to_owned(),
            }),
            SaltedRef::Element(SaltedElementRef { salt, value }) => Self::Element(SaltedElement { salt, value: value.to_owned() }),
            SaltedRef::Decoy(decoy) => Self::Decoy(decoy),
        }
    }
}

impl<'a, T: CwtAny> From<&'a Salted<T>> for SaltedRef<'a, T> {
    fn from(s: &'a Salted<T>) -> Self {
        match s {
            Salted::Claim(SaltedClaim { salt, value, name }) => Self::Claim(SaltedClaimRef { salt: *salt, value, name }),
            Salted::Element(SaltedElement { salt, value }) => Self::Element(SaltedElementRef { salt: *salt, value }),
            Salted::Decoy(decoy) => Self::Decoy(*decoy),
        }
    }
}

pub type SaltedArrayWithDigests<'a> = HashMap<Vec<u8>, Cow<'a, Salted<Value>>>;
pub type SaltedArrayToVerify<'a> = Vec<(Cow<'a, Salted<Value>>, Option<Vec<u8>>)>;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SaltedArray(pub Vec<InlinedCbor<Salted<Value>>>);

impl SaltedArray {
    pub fn new() -> Self {
        Self(Vec::with_capacity(0))
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Adds the item to the array and return a reference to it in order to hash it later
    pub fn push_ref<'a, T: CwtAny + 'a>(&'a mut self, salted: impl Into<SaltedRef<'a, T>>) -> EsdicawtSpecResult<Value> {
        self.0.push(Salted::from(salted.into()).upcast()?.into());
        // SAFETY: we just inserted the item in the array so '.last_mut()' cannot fail
        Ok(self.0.last_mut().map(InlinedCbor::to_value).transpose()?.map(Value::serialized).transpose()?.unwrap())
    }

    pub fn as_iter(&self) -> impl Iterator<Item = EsdicawtSpecResult<Cow<'_, Salted<Value>>>> + '_ {
        self.0.iter().map(InlinedCbor::as_value)
    }

    pub fn iter_clone(&self) -> impl Iterator<Item = EsdicawtSpecResult<Salted<Value>>> {
        self.0.iter().map(InlinedCbor::clone_value)
    }

    pub fn iter(&mut self) -> impl Iterator<Item = EsdicawtSpecResult<&Salted<Value>>> + '_ {
        self.0.iter_mut().map(InlinedCbor::to_value)
    }

    pub fn take_into_iter(self) -> impl Iterator<Item = EsdicawtSpecResult<Salted<Value>>> {
        self.0.into_iter().map(InlinedCbor::try_into_value)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = EsdicawtSpecResult<&mut Salted<Value>>> + '_ {
        self.0.iter_mut().map(InlinedCbor::to_value_mut)
    }

    /// Returns a salted with all the digests already computed to avoid doing it many times
    pub fn digested<Hasher: digest::Digest>(&self) -> EsdicawtSpecResult<SaltedArrayWithDigests<'_>> {
        self.as_iter()
            .map(|d| match d {
                Ok(salted) => {
                    let bytes = salted.to_cbor_bytes()?;
                    let digest = Hasher::digest(&bytes[..]).to_vec();
                    Ok((digest, salted))
                }
                Err(e) => Err(e),
            })
            .collect::<EsdicawtSpecResult<HashMap<_, _>>>()
    }

    /// Returns a salted array with room to dynamically insert the digest of each salted to cache it
    pub fn to_verify(&self) -> EsdicawtSpecResult<SaltedArrayToVerify<'_>> {
        self.as_iter()
            .map(|d| match d {
                Ok(salted) => Ok((salted, None)),
                Err(e) => Err(e),
            })
            .collect::<EsdicawtSpecResult<Vec<_>>>()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
