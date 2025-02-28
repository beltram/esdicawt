use crate::EsdicawtSpecResult;
use ciborium::Value;
use serde::ser::SerializeSeq;

use super::{ClaimName, CwtAny, Salt};

#[derive(Debug, Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedElement<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple)]
pub struct SaltedElementRef<'a, T: CwtAny> {
    pub salt: &'a Salt,
    pub value: &'a T,
}

// Do not change the order of the claims !!!
#[derive(Debug, Clone, Eq, PartialEq, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct SaltedClaim<T: CwtAny> {
    pub salt: Salt,
    pub value: T,
    pub name: ClaimName,
}

// Do not change the order of the claims !!!
#[derive(Debug, Clone, serde_tuple::Serialize_tuple)]
pub struct SaltedClaimRef<'a, T: CwtAny> {
    pub salt: &'a Salt,
    pub value: &'a T,
    pub claim: &'a ClaimName,
}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple, serde_tuple::Deserialize_tuple)]
pub struct Decoy {
    pub salt: (Salt,),
}

impl PartialEq for Decoy {
    fn eq(&self, other: &Self) -> bool {
        self.salt.0.eq(&other.salt.0)
    }
}

impl Eq for Decoy {}

#[derive(Debug, Clone, serde_tuple::Serialize_tuple)]
pub struct DecoyRef<'a> {
    pub salt: (&'a Salt,),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Salted<T: serde::Serialize + for<'d> serde::Deserialize<'d>> {
    Claim(SaltedClaim<T>),
    Element(SaltedElement<T>),
    Decoy(Decoy),
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
                let name = seq.next_element::<ClaimName>()?;

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
    Decoy(DecoyRef<'a>),
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

impl<'a, T: CwtAny> From<DecoyRef<'a>> for SaltedRef<'a, T> {
    fn from(v: DecoyRef<'a>) -> Self {
        Self::Decoy(v)
    }
}

#[derive(Default, Debug, Clone, PartialEq)]
pub struct SaltedArray(pub Vec<Value>);

impl serde::Serialize for SaltedArray {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for value in &self.0 {
            let mut buf = vec![];
            ciborium::into_writer(value, &mut buf).map_err(|e| S::Error::custom(format!("cannot serialize Salted value: {e}")))?;

            seq.serialize_element(&buf)?;
        }
        seq.end()
    }
}

impl<'de> serde::Deserialize<'de> for SaltedArray {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SaltedArrayVisitor;

        impl<'de> serde::de::Visitor<'de> for SaltedArrayVisitor {
            type Value = SaltedArray;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a salted-array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error as _;
                let size = seq.size_hint().unwrap_or(0);

                // SAFETY: passing raw size can cause a capacity overflow https://doc.rust-lang.org/std/vec/struct.Vec.html#guarantees
                const MAX_SIZE: usize = isize::MAX as usize / std::mem::size_of::<Value>();
                if size > MAX_SIZE {
                    return Err(A::Error::custom("seq too big"));
                }

                let mut list = Vec::with_capacity(size);
                while let Some(value_raw) = seq.next_element::<Vec<u8>>()? {
                    let value: Value = ciborium::from_reader(&value_raw[..]).map_err(|err| A::Error::custom(format!("Cannot deserialize SaltedArray Bstr: {err}")))?;
                    list.push(value);
                }

                Ok(SaltedArray(list))
            }
        }

        deserializer.deserialize_seq(SaltedArrayVisitor)
    }
}

impl SaltedArray {
    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    /// Adds the item to the array and return a reference to it to hash it later
    pub fn push_ref<'a, T: CwtAny + 'a>(&'a mut self, salted: impl Into<SaltedRef<'a, T>>) -> Result<&'a Value, ciborium::value::Error> {
        let salted = Value::serialized(&salted.into())?;
        self.0.push(salted);
        // SAFETY: we just inserted the item in the array so '.last()' cannot fail
        Ok(self.0.last().unwrap())
    }

    pub fn iter(&self) -> impl Iterator<Item = EsdicawtSpecResult<Salted<Value>>> + '_ {
        self.0.iter().map(|v| v.deserialized().map_err(Into::into))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}
