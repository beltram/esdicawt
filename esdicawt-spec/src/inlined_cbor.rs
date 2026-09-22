use super::{CwtAny, EsdicawtSpecResult};
use ciborium::Value;
use std::sync::OnceLock;

#[derive(Clone)]
pub enum InlinedCbor<T: CwtAny> {
    Bytes(Vec<u8>, OnceLock<T>),
    Value(T, OnceLock<Vec<u8>>),
}

impl<T: CwtAny> PartialEq for InlinedCbor<T> {
    fn eq(&self, other: &Self) -> bool {
        match (self.to_bytes(), other.to_bytes()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }
}

impl<T: CwtAny> Eq for InlinedCbor<T> {}

impl<T: CwtAny + std::fmt::Debug> std::fmt::Debug for InlinedCbor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct(std::any::type_name::<T>());
        match self {
            Self::Value(v, _) => s.field("value", v),
            Self::Bytes(_, v) if let Some(v) = v.get() => s.field("value", v),
            Self::Bytes(b, _) => s.field("bytes", b),
        }
        .finish()
    }
}

impl<T: CwtAny> serde::Serialize for InlinedCbor<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let b = self.to_bytes().map_err(S::Error::custom)?;
        serde_bytes::serialize(b, serializer)
    }
}

impl<'de, T: CwtAny> serde::Deserialize<'de> for InlinedCbor<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::deserialize::<Vec<u8>, _>(deserializer)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl<T: CwtAny> InlinedCbor<T> {
    /// Using the deserialized value could cause some issues as working with heterogeneous arrays is tricky (requires
    /// wrapping all the Array elements) or also nested redacted claim keys could get elided.
    /// Hence, it's better to use the raw value from the raw bytes.
    ///
    /// This method should only be used internally by this library when trying to do a lookup.
    pub fn upcast_value(&self) -> EsdicawtSpecResult<Value> {
        Ok(match self {
            Self::Bytes(bytes, _) => Value::from_cbor_bytes(bytes)?,
            Self::Value(_, bytes) if let Some(bytes) = bytes.get() => Value::from_cbor_bytes(bytes)?,
            #[allow(unused)]
            Self::Value(v, _) => {
                #[cfg(debug_assertions)]
                panic!("Trying to upcast to value without the raw bytes, some elements might have been redacted in the process");

                #[cfg(not(debug_assertions))]
                v.to_cbor_value()?
            }
        })
    }

    /// Mutates the value then re-encodes the raw bytes so that both stay in sync
    #[cfg(any(test, feature = "test-utils"))]
    pub fn modify<R>(&mut self, f: impl FnOnce(&mut T) -> R) -> EsdicawtSpecResult<R> {
        match self {
            Self::Value(v, bytes) => {
                // drop the stale bytes first so that we stay consistent should the encoding fail
                bytes.take();
                let r = f(v);
                *bytes = OnceLock::from(v.to_cbor_bytes()?);
                Ok(r)
            }
            Self::Bytes(bytes, cached) => {
                let mut v = match cached.take() {
                    Some(v) => v,
                    None => T::from_cbor_bytes(bytes)?,
                };
                let r = f(&mut v);
                match v.to_cbor_bytes() {
                    Ok(b) => *self = Self::Bytes(b, OnceLock::from(v)),
                    Err(e) => {
                        *self = Self::Value(v, OnceLock::new());
                        return Err(e);
                    }
                }
                Ok(r)
            }
        }
    }

    pub fn replace_value(&mut self, value: T) -> EsdicawtSpecResult<()> {
        *self = Self::Bytes(value.to_cbor_bytes()?, OnceLock::from(value));
        Ok(())
    }

    /// Decodes the value once and caches it
    pub fn to_value(&self) -> EsdicawtSpecResult<&T> {
        match self {
            Self::Value(v, _) => Ok(v),
            Self::Bytes(_, v) if let Some(v) = v.get() => Ok(v),
            Self::Bytes(b, v) => {
                // might race with another thread, in which case the first decoded value wins, which is fine since both are equal
                let decoded = T::from_cbor_bytes(b)?;
                Ok(v.get_or_init(|| decoded))
            }
        }
    }

    /// Encodes the value once and caches it
    pub fn to_bytes(&self) -> EsdicawtSpecResult<&[u8]> {
        match self {
            Self::Bytes(b, _) => Ok(b),
            Self::Value(_, b) if let Some(b) = b.get() => Ok(b),
            Self::Value(v, b) => {
                // might race with another thread, in which case the first encoded value wins, which is fine since both are equal
                let encoded = v.to_cbor_bytes()?;
                Ok(b.get_or_init(|| encoded))
            }
        }
    }

    // conflicting with `impl From<T>`
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self::Bytes(b, OnceLock::new())
    }

    pub fn try_into_value(self) -> EsdicawtSpecResult<T> {
        Ok(match self {
            Self::Value(v, _) => v,
            Self::Bytes(b, v) => match v.into_inner() {
                Some(v) => v,
                None => T::from_cbor_bytes(&b)?,
            },
        })
    }
}

// to use with caution
impl<T: CwtAny> From<T> for InlinedCbor<T> {
    fn from(v: T) -> Self {
        Self::Value(v, OnceLock::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::Value;

    #[test]
    fn should_serialize_as_bstr() {
        let value = InlinedCbor::from(0u32);
        let ser = value.to_cbor_bytes().unwrap();
        assert_eq!(ser, vec![0b010_00001, 0b0000_0000]);
    }

    #[test]
    fn should_deserialize_from_bstr() {
        let ser: Vec<u8> = vec![0b010_00001, 0b0000_0000];
        let value = InlinedCbor::<u32>::from_cbor_bytes(&ser).unwrap();
        assert_eq!(*value.to_value().unwrap(), 0);
    }

    fn assert_serializes_modified_value(mut value: InlinedCbor<u32>) {
        value.modify(|v| *v = 1).unwrap();
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![1]);

        value.replace_value(2).unwrap();
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![2]);

        value.modify(|v| *v = 3).unwrap();
        assert_eq!(value.to_bytes().unwrap().to_vec(), vec![3]);

        value.modify(|v| *v = 4).unwrap();
        assert_eq!(value.to_bytes().unwrap().to_vec(), vec![4]);

        value.modify(|v| *v = 5).unwrap();
        assert_eq!(value.to_bytes().unwrap().to_vec(), vec![5]);
        assert_eq!(value.upcast_value().unwrap(), Value::from(5));
    }

    #[test]
    fn should_serialize_modified_value() {
        assert_serializes_modified_value(InlinedCbor::from(0u32));
        assert_serializes_modified_value(InlinedCbor::from_bytes(0u32.to_cbor_bytes().unwrap()));
    }

    #[test]
    fn should_equal_regardless_of_cache() {
        let bytes = 42u32.to_cbor_bytes().unwrap();
        let (a, b) = (InlinedCbor::<u32>::from_bytes(bytes.clone()), InlinedCbor::<u32>::from_bytes(bytes));
        a.to_value().unwrap();
        assert_eq!(a, b);
        assert_eq!(a, InlinedCbor::from(42u32));
        assert_ne!(a, InlinedCbor::from(43u32));
    }
}
