use super::{CwtAny, EsdicawtSpecResult};
use ciborium::Value;

#[derive(Clone, Eq, PartialEq)]
pub enum InlinedCbor<T: CwtAny> {
    Bytes(Vec<u8>, Option<T>),
    Value(T, Option<Vec<u8>>),
}

impl<T: CwtAny + std::fmt::Debug> std::fmt::Debug for InlinedCbor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct(std::any::type_name::<T>());
        match self {
            Self::Bytes(_, Some(v)) | Self::Value(v, _) => s.field("value", v),
            Self::Bytes(b, None) => s.field("bytes", b),
        }
        .finish()
    }
}

impl<T: CwtAny> serde::Serialize for InlinedCbor<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => serde_bytes::serialize(b, serializer),
            Self::Value(v, None) => {
                use serde::ser::Error as _;
                let b = v.to_cbor_bytes().map_err(S::Error::custom)?;
                serde_bytes::serialize(&b, serializer)
            }
        }
    }
}

impl<'de, T: CwtAny> serde::Deserialize<'de> for InlinedCbor<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::deserialize::<Vec<u8>, _>(deserializer)?;
        Ok(Self::Bytes(bytes, None))
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
            Self::Bytes(bytes, _) | Self::Value(_, Some(bytes)) => Value::from_cbor_bytes(bytes)?,
            #[allow(unused)]
            Self::Value(v, None) => {
                #[cfg(debug_assertions)]
                panic!("Trying to upcast to value without the raw bytes, some elements might have been redacted in the process");

                #[cfg(not(debug_assertions))]
                v.to_cbor_value()?
            }
        })
    }

    /// Mutates the value then re-encodes the raw bytes so that both stay in sync
    #[cfg(test)]
    pub fn modify<R>(&mut self, f: impl FnOnce(&mut T) -> R) -> EsdicawtSpecResult<R> {
        match self {
            Self::Value(v, bytes) => {
                // drop the stale bytes first so that we stay consistent should the encoding fail
                *bytes = None;
                let r = f(v);
                bytes.replace(v.to_cbor_bytes()?);
                Ok(r)
            }
            Self::Bytes(bytes, cached) => {
                let mut v = match cached.take() {
                    Some(v) => v,
                    None => T::from_cbor_bytes(bytes)?,
                };
                let r = f(&mut v);
                match v.to_cbor_bytes() {
                    Ok(b) => *self = Self::Bytes(b, Some(v)),
                    Err(e) => {
                        *self = Self::Value(v, None);
                        return Err(e);
                    }
                }
                Ok(r)
            }
        }
    }

    pub fn replace_value(&mut self, value: T) -> EsdicawtSpecResult<()> {
        *self = Self::Bytes(value.to_cbor_bytes()?, Some(value));
        Ok(())
    }

    pub fn as_value(&self) -> EsdicawtSpecResult<std::borrow::Cow<'_, T>> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(std::borrow::Cow::Borrowed(v)),
            Self::Bytes(b, None) => Ok(std::borrow::Cow::Owned(T::from_cbor_bytes(b)?)),
        }
    }

    pub fn clone_value(&self) -> EsdicawtSpecResult<T> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(v.clone()),
            Self::Bytes(b, None) => Ok(T::from_cbor_bytes(b)?),
        }
    }

    pub fn to_value(&mut self) -> EsdicawtSpecResult<&T> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(v),
            Self::Bytes(b, v) => Ok(v.insert(T::from_cbor_bytes(b)?)),
        }
    }

    pub fn to_bytes(&mut self) -> EsdicawtSpecResult<&[u8]> {
        match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => Ok(b),
            Self::Value(v, b ) => Ok(b.insert(v.to_cbor_bytes()?)),
        }
    }

    pub fn clone_bytes(&self) -> EsdicawtSpecResult<Vec<u8>> {
        Ok(match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => b.clone(),
            Self::Value(v, None) => v.to_cbor_bytes()?,
        })
    }

    pub fn as_bytes(&self) -> EsdicawtSpecResult<std::borrow::Cow<'_, [u8]>> {
        Ok(match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => std::borrow::Cow::Borrowed(b),
            Self::Value(v, None) => std::borrow::Cow::Owned(T::to_cbor_bytes(v)?),
        })
    }

    // conflicting with `impl From<T>`
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self::Bytes(b, None)
    }

    pub fn try_into_value(self) -> EsdicawtSpecResult<T> {
        Ok(match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => v,
            Self::Bytes(b, None) => T::from_cbor_bytes(&b)?,
        })
    }
}

// to use with caution
impl<T: CwtAny> From<T> for InlinedCbor<T> {
    fn from(v: T) -> Self {
        Self::Value(v, None)
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
        assert_eq!(value.clone_value().unwrap(), 0);
    }

    fn assert_serializes_modified_value(mut value: InlinedCbor<u32>) {
        value.modify(|v| *v = 1).unwrap();
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![1]);

        value.replace_value(2).unwrap();
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![2]);

        value.modify(|v| *v = 3).unwrap();
        assert_eq!(value.as_bytes().unwrap().to_vec(), vec![3]);

        value.modify(|v| *v = 4).unwrap();
        assert_eq!(value.clone_bytes().unwrap(), vec![4]);

        value.modify(|v| *v = 5).unwrap();
        assert_eq!(value.to_bytes().unwrap().to_vec(), vec![5]);
        assert_eq!(value.upcast_value().unwrap(), Value::from(5));
    }

    #[test]
    fn should_serialize_modified_value() {
        assert_serializes_modified_value(InlinedCbor::from(0u32));
        assert_serializes_modified_value(InlinedCbor::from_bytes(0u32.to_cbor_bytes().unwrap()));
    }
}
