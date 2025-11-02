use super::{CwtAny, EsdicawtSpecError, EsdicawtSpecResult};

#[derive(Clone, Eq, PartialEq)]
pub enum InlinedCbor<T: CwtAny> {
    // bool stands for "modified" and is true when the value has been mutably borrowed
    Bytes(Vec<u8>, Option<T>, bool),
    Value(T, Option<Vec<u8>>, bool),
}

impl<T: CwtAny + std::fmt::Debug> std::fmt::Debug for InlinedCbor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct(std::any::type_name::<T>());
        match self {
            Self::Bytes(_, Some(v), ..) | Self::Value(v, ..) => s.field("value", v),
            Self::Bytes(b, ..) => s.field("bytes", b),
        }
        .finish()
    }
}

impl<T: CwtAny> serde::Serialize for InlinedCbor<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        match self {
            Self::Value(_, Some(b), false) | Self::Bytes(b, _, false) => serde_bytes::serialize(b, serializer),
            Self::Value(v, ..) | Self::Bytes(_, Some(v), true) => {
                use serde::ser::Error as _;
                let b = v.to_cbor_bytes().map_err(S::Error::custom)?;
                serde_bytes::serialize(&b, serializer)
            }
            Self::Bytes(_, None, true) => Err(S::Error::custom("InlineCbor implementation error")),
        }
    }
}

impl<'de, T: CwtAny> serde::Deserialize<'de> for InlinedCbor<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = serde_bytes::deserialize::<Vec<u8>, _>(deserializer)?;
        Ok(Self::Bytes(bytes, None, false))
    }
}

impl<T: CwtAny> InlinedCbor<T> {
    pub fn as_value(&self) -> EsdicawtSpecResult<std::borrow::Cow<'_, T>> {
        match self {
            Self::Value(v, ..) | Self::Bytes(_, Some(v), ..) => Ok(std::borrow::Cow::Borrowed(v)),
            Self::Bytes(b, ..) => Ok(std::borrow::Cow::Owned(T::from_cbor_bytes(b)?)),
        }
    }

    pub fn clone_value(&self) -> EsdicawtSpecResult<T> {
        match self {
            Self::Value(v, ..) | Self::Bytes(_, Some(v), ..) => Ok(v.clone()),
            Self::Bytes(b, ..) => Ok(T::from_cbor_bytes(b)?),
        }
    }

    pub fn to_value(&mut self) -> EsdicawtSpecResult<&T> {
        match self {
            Self::Value(v, ..) | Self::Bytes(_, Some(v), ..) => Ok(v),
            Self::Bytes(b, v, ..) => {
                v.replace(T::from_cbor_bytes(b)?);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(v.as_ref().unwrap())
            }
        }
    }
    
    pub fn to_value_mut(&mut self) -> EsdicawtSpecResult<&mut T> {
        match self {
            Self::Value(v, _, modified) | Self::Bytes(_, Some(v), modified) => {
                *modified = true;
                Ok(v)
            }
            Self::Bytes(b, v, modified) => {
                *modified = true;
                v.replace(T::from_cbor_bytes(b)?);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(v.as_mut().unwrap())
            }
        }
    }

    pub fn to_bytes(&mut self) -> EsdicawtSpecResult<&[u8]> {
        match self {
            Self::Bytes(b, _, false) | Self::Value(_, Some(b), false) => Ok(b),
            Self::Bytes(b, Some(v), true) => {
                *b = v.to_cbor_bytes()?;
                Ok(b)
            }
            Self::Value(v, b, ..) => {
                let bytes = v.to_cbor_bytes()?;
                b.replace(bytes);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(b.as_ref().unwrap())
            }
            Self::Bytes(_, None, true) => Err(EsdicawtSpecError::ImplementationError("InlineCbor implementation error")),
        }
    }

    pub fn clone_bytes(&self) -> EsdicawtSpecResult<Vec<u8>> {
        Ok(match self {
            Self::Bytes(b, _, false) | Self::Value(_, Some(b), false) => b.clone(),
            Self::Value(v, ..) | Self::Bytes(_, Some(v), true) => v.to_cbor_bytes()?,
            Self::Bytes(_, None, true) => return Err(EsdicawtSpecError::ImplementationError("InlineCbor implementation error")),
        })
    }

    pub fn as_bytes(&self) -> EsdicawtSpecResult<std::borrow::Cow<'_, [u8]>> {
        Ok(match self {
            Self::Bytes(b, _, false) | Self::Value(_, Some(b), false) => std::borrow::Cow::Borrowed(b),
            Self::Value(v, ..) | Self::Bytes(_, Some(v), true) => std::borrow::Cow::Owned(T::to_cbor_bytes(v)?),
            Self::Bytes(_, None, true) => return Err(EsdicawtSpecError::ImplementationError("InlineCbor implementation error")),
        })
    }

    pub fn to_pair_mut(&mut self) -> EsdicawtSpecResult<(&mut T, &[u8])> {
        match self {
            Self::Value(v, Some(b), modified) | Self::Bytes(b, Some(v), modified) => {
                *modified = true;
                Ok((v, b))
            }
            Self::Value(v, b, modified) => {
                *modified = true;
                b.replace(v.to_cbor_bytes()?);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok((v, b.as_ref().unwrap()))
            }
            Self::Bytes(b, v, modified) => {
                *modified = true;
                v.replace(T::from_cbor_bytes(b)?);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok((v.as_mut().unwrap(), b))
            }
        }
    }

    // conflicting with `impl From<T>`
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self::Bytes(b, None, false)
    }

    pub fn try_into_value(self) -> EsdicawtSpecResult<T> {
        Ok(match self {
            Self::Value(v, ..) | Self::Bytes(_, Some(v), ..) => v,
            Self::Bytes(b, ..) => T::from_cbor_bytes(&b)?,
        })
    }
}

impl<T: CwtAny> From<T> for InlinedCbor<T> {
    fn from(v: T) -> Self {
        Self::Value(v, None, false)
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

    #[test]
    fn should_serialize_modified_value() {
        let mut value = InlinedCbor::from(0u32);
        *value.to_value_mut().unwrap() = 1;
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![1]);

        let (v, _) = value.to_pair_mut().unwrap();
        *v = 2;
        let deser = Value::from_cbor_bytes(&value.to_cbor_bytes().unwrap()).unwrap();
        assert_eq!(deser.into_bytes().unwrap(), vec![2]);

        *value.to_value_mut().unwrap() = 3;
        assert_eq!(value.as_bytes().unwrap().to_vec(), vec![3]);

        *value.to_value_mut().unwrap() = 4;
        assert_eq!(value.clone_bytes().unwrap(), vec![4]);

        *value.to_value_mut().unwrap() = 5;
        assert_eq!(value.to_bytes().unwrap().to_vec(), vec![5]);
    }
}
