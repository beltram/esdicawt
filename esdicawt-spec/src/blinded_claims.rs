use super::{CwtAny, EsdicawtSpecError, Salt, SdCwtClaim};
use crate::{EsdicawtSpecResult, inlined_cbor::InlinedCbor, redacted_claims::ToRedacted};
use ciborium::Value;
use serde::ser::SerializeSeq;
use std::{borrow::Cow, collections::HashMap};

mod lazy_redacted;

pub use lazy_redacted::LazyRedacted;

#[derive(Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedElement<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
}

impl<T: CwtAny> ToRedacted for SaltedElement<T> {}

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

impl<'a, T: CwtAny> ToRedacted for SaltedElementRef<'a, T> {}

// Do not change the order of the claims !!!
#[derive(Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedClaim<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
    pub name: SdCwtClaim,
}

impl<T: CwtAny> ToRedacted for SaltedClaim<T> {}

impl<T: CwtAny> std::fmt::Debug for SaltedClaim<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(value) = self.value.to_cbor_value() {
            write!(f, "{:?}: {value:?} [{:?}]", self.name, self.salt)
        } else {
            write!(f, "{:?}: ??? [{:?}]", self.name, self.salt)
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

impl<'a, T: CwtAny> ToRedacted for SaltedClaimRef<'a, T> {}

#[derive(Debug, Clone, Copy, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct Decoy {
    pub salt: (Salt,),
}

impl ToRedacted for Decoy {}

impl PartialEq for Decoy {
    fn eq(&self, other: &Self) -> bool {
        self.salt.0.eq(&other.salt.0)
    }
}

impl Eq for Decoy {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SaltedEntry<T: CwtAny> {
    Claim(SaltedClaim<T>),
    Element(SaltedElement<T>),
    Decoy(Decoy),
}

impl<T: CwtAny> SaltedEntry<T> {
    pub fn upcast(self) -> EsdicawtSpecResult<SaltedEntry<Value>> {
        Ok(match self {
            Self::Claim(SaltedClaim { salt, value, name }) => SaltedEntry::<Value>::Claim(SaltedClaim {
                salt,
                value: value.to_cbor_value()?,
                name,
            }),
            Self::Element(SaltedElement { salt, value }) => SaltedEntry::<Value>::Element(SaltedElement {
                salt,
                value: value.to_cbor_value()?,
            }),
            Self::Decoy(salt) => SaltedEntry::<Value>::Decoy(salt),
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

impl<T: CwtAny> ToRedacted for SaltedEntry<T> {}

impl<T: CwtAny> serde::Serialize for SaltedEntry<T> {
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

impl<'de, T: CwtAny> serde::Deserialize<'de> for SaltedEntry<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SaltedVisitor<T: CwtAny>(core::marker::PhantomData<T>);

        impl<'de, T: CwtAny> serde::de::Visitor<'de> for SaltedVisitor<T> {
            type Value = SaltedEntry<T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a salted disclosure")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let salt = seq.next_element::<Salt>()?.ok_or_else(|| A::Error::custom("Missing salt in salted"))?;
                let value = seq.next_element::<T>()?;
                let name = seq.next_element::<SdCwtClaim>()?;

                Ok(match (salt, value, name) {
                    (salt, None, None) => SaltedEntry::Decoy(Decoy { salt: (salt,) }),
                    (salt, Some(value), None) => SaltedEntry::Element(SaltedElement { salt, value }),
                    (salt, Some(value), Some(name)) => SaltedEntry::Claim(SaltedClaim { salt, value, name }),
                    _ => return Err(A::Error::custom("Invalid disclosure")),
                })
            }
        }

        deserializer.deserialize_seq(SaltedVisitor(Default::default()))
    }
}

impl<T: CwtAny> From<SaltedClaim<T>> for SaltedEntry<T> {
    fn from(v: SaltedClaim<T>) -> Self {
        Self::Claim(v)
    }
}

impl<T: CwtAny> From<SaltedElement<T>> for SaltedEntry<T> {
    fn from(v: SaltedElement<T>) -> Self {
        Self::Element(v)
    }
}

impl<T: CwtAny> From<Decoy> for SaltedEntry<T> {
    fn from(v: Decoy) -> Self {
        Self::Decoy(v)
    }
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(untagged, bound = "T: CwtAny")]
pub enum SaltedEntryRef<'a, T: CwtAny> {
    Claim(SaltedClaimRef<'a, T>),
    Element(SaltedElementRef<'a, T>),
    Decoy(Decoy),
}

impl<'a, T: CwtAny> ToRedacted for SaltedEntryRef<'a, T> {}

impl<'a, T: CwtAny> From<SaltedClaimRef<'a, T>> for SaltedEntryRef<'a, T> {
    fn from(v: SaltedClaimRef<'a, T>) -> Self {
        Self::Claim(v)
    }
}

impl<'a, T: CwtAny> From<SaltedElementRef<'a, T>> for SaltedEntryRef<'a, T> {
    fn from(v: SaltedElementRef<'a, T>) -> Self {
        Self::Element(v)
    }
}

impl<T: CwtAny> From<Decoy> for SaltedEntryRef<'_, T> {
    fn from(v: Decoy) -> Self {
        Self::Decoy(v)
    }
}

impl<'a, T: CwtAny> From<SaltedEntryRef<'a, T>> for SaltedEntry<T> {
    fn from(s: SaltedEntryRef<'a, T>) -> Self {
        match s {
            SaltedEntryRef::Claim(SaltedClaimRef { salt, value, name }) => Self::Claim(SaltedClaim {
                salt,
                value: value.to_owned(),
                name: name.to_owned(),
            }),
            SaltedEntryRef::Element(SaltedElementRef { salt, value }) => Self::Element(SaltedElement { salt, value: value.to_owned() }),
            SaltedEntryRef::Decoy(decoy) => Self::Decoy(decoy),
        }
    }
}

impl<'a, T: CwtAny> From<&'a SaltedEntry<T>> for SaltedEntryRef<'a, T> {
    fn from(s: &'a SaltedEntry<T>) -> Self {
        match s {
            SaltedEntry::Claim(SaltedClaim { salt, value, name }) => Self::Claim(SaltedClaimRef { salt: *salt, value, name }),
            SaltedEntry::Element(SaltedElement { salt, value }) => Self::Element(SaltedElementRef { salt: *salt, value }),
            SaltedEntry::Decoy(decoy) => Self::Decoy(*decoy),
        }
    }
}

pub type SaltedArrayWithDigests<'a> = HashMap<Vec<u8>, Cow<'a, SaltedEntry<Value>>>;
pub type SaltedArrayToVerify<'a> = Vec<(Cow<'a, SaltedEntry<Value>>, LazyRedacted)>;

#[derive(Default, Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SaltedArray(pub Vec<InlinedCbor<SaltedEntry<Value>>>);

impl SaltedArray {
    pub fn new() -> Self {
        Self(Vec::with_capacity(0))
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Adds the item to the array
    pub fn push_ref_bytes<'a, T: CwtAny + 'a>(&'a mut self, salted: impl Into<SaltedEntryRef<'a, T>>) -> EsdicawtSpecResult<()> {
        self.0.push(SaltedEntry::from(salted.into()).upcast()?.into());
        Ok(())
    }

    pub fn as_iter(&self) -> impl Iterator<Item = EsdicawtSpecResult<Cow<'_, SaltedEntry<Value>>>> + '_ {
        self.0.iter().map(InlinedCbor::as_value)
    }

    pub fn iter_clone(&self) -> impl Iterator<Item = EsdicawtSpecResult<SaltedEntry<Value>>> {
        self.0.iter().map(InlinedCbor::clone_value)
    }

    pub fn iter(&mut self) -> impl Iterator<Item = EsdicawtSpecResult<&SaltedEntry<Value>>> + '_ {
        self.0.iter_mut().map(InlinedCbor::to_value)
    }

    pub fn take_into_iter(self) -> impl Iterator<Item = EsdicawtSpecResult<SaltedEntry<Value>>> {
        self.0.into_iter().map(InlinedCbor::try_into_value)
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = EsdicawtSpecResult<&mut SaltedEntry<Value>>> + '_ {
        self.0.iter_mut().map(InlinedCbor::to_value_mut)
    }

    /// Returns a salted with all the digests already computed to avoid doing it many times
    pub fn digested<H: digest::Digest>(&self) -> EsdicawtSpecResult<SaltedArrayWithDigests<'_>> {
        #[cfg(not(feature = "backward"))]
        fn salted_redacted<H: digest::Digest>(salted_entry: &InlinedCbor<SaltedEntry<Value>>) -> EsdicawtSpecResult<impl Iterator<Item = (Vec<u8>, Cow<'_, SaltedEntry<Value>>)>> {
            let value = salted_entry.as_value()?;
            let digest = value.as_ref().to_redacted::<H>()?.to_vec();
            Ok(std::iter::once((digest, value)))
        }

        #[cfg(feature = "backward")]
        fn salted_redacted<H: digest::Digest>(salted_entry: &InlinedCbor<SaltedEntry<Value>>) -> EsdicawtSpecResult<impl Iterator<Item = (Vec<u8>, Cow<'_, SaltedEntry<Value>>)>> {
            let value = salted_entry.as_value()?;
            let digest = value.as_ref().to_redacted::<H>()?.to_vec();
            let old_digest = value.as_ref().old_to_redacted::<H>()?.to_vec();
            Ok(std::iter::chain(std::iter::once((digest, value.clone())), std::iter::once((old_digest, value))))
        }

        let size = self.0.len();
        let digested = self
            .0
            .iter()
            .map(|salted_entry| salted_redacted::<H>(salted_entry))
            .collect::<EsdicawtSpecResult<Vec<_>>>()?
            .into_iter()
            .flatten()
            .collect::<HashMap<_, _>>();
        #[cfg(not(feature = "backward"))]
        if size != digested.len() {
            return Err(EsdicawtSpecError::DuplicateDisclosure);
        }
        #[cfg(feature = "backward")]
        if size * 2 != digested.len() {
            return Err(EsdicawtSpecError::DuplicateDisclosure);
        }
        Ok(digested)
    }

    /// Returns a salted array with room to dynamically insert the digest of each salted to cache it
    pub fn to_verify(&self) -> EsdicawtSpecResult<SaltedArrayToVerify<'_>> {
        self.as_iter()
            .map(|d| match d {
                Ok(salted) => Ok((salted, Default::default())),
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

#[cfg(test)]
mod tests {
    use super::*;

    // see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt-08#name-sha-256-hash-of-inspector_l
    #[test]
    fn should_verify_spec_salted_claim_example() {
        let salt = "bae611067bb823486797da1ebbb52f83";
        let salt = Salt(hex::decode(salt).unwrap().try_into().unwrap());
        let value = "ABCD-123456".to_string();
        let name = SdCwtClaim::Int(501);

        let salted_claim = SaltedClaim { salt, value, name };
        let salted_entry = SaltedEntry::Claim(salted_claim);
        let redacted_claim_hash = salted_entry.to_redacted::<sha2::Sha256>().unwrap();
        assert_eq!(hex::encode(&*redacted_claim_hash), "af375dc3fba1d082448642c00be7b2f7bb05c9d8fb61cfc230ddfdfb4616a693");
    }
}
