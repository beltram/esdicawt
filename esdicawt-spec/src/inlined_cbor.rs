use super::{CwtAny, EsdicawtSpecResult};

#[derive(Clone, PartialEq)]
pub enum InlinedCbor<T: CwtAny> {
    Bytes(Vec<u8>, Option<T>),
    Value(T, Option<Vec<u8>>),
}

impl<T: CwtAny + std::fmt::Debug> std::fmt::Debug for InlinedCbor<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct(std::any::type_name::<T>());
        match self {
            Self::Bytes(_, Some(v)) | Self::Value(v, _) => s.field("value", v),
            Self::Bytes(b, _) => s.field("bytes", b),
        }
        .finish()
    }
}

impl<T: CwtAny> serde::Serialize for InlinedCbor<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Value(_, Some(b)) | Self::Bytes(b, _) => serde_bytes::serialize(b, serializer),
            Self::Value(v, _) => {
                use serde::ser::Error as _;
                let b = v.to_cbor_bytes().map_err(S::Error::custom)?;
                serde_bytes::serialize(&b, serializer)
            }
        }
    }
}

impl<'de, T: CwtAny> serde::Deserialize<'de> for InlinedCbor<T> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        let value = ciborium::from_reader(&bytes[..]).map_err(|e| D::Error::custom(format!("Cannot deserialize inner value from CBOR: {e}")))?;
        Ok(Self::Value(value, Some(bytes)))
    }
}

impl<T: CwtAny> InlinedCbor<T> {
    pub fn as_value(&self) -> EsdicawtSpecResult<std::borrow::Cow<'_, T>> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(std::borrow::Cow::Borrowed(v)),
            Self::Bytes(b, _) => Ok(std::borrow::Cow::Owned(T::from_cbor_bytes(b)?)),
        }
    }

    pub fn clone_value(&self) -> EsdicawtSpecResult<T> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(v.clone()),
            Self::Bytes(b, _) => Ok(T::from_cbor_bytes(b)?),
        }
    }

    pub fn to_value(&mut self) -> EsdicawtSpecResult<&T> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(v),
            Self::Bytes(b, v) => {
                let value = T::from_cbor_bytes(b)?;
                v.replace(value);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(v.as_ref().unwrap())
            }
        }
    }

    pub fn to_value_mut(&mut self) -> EsdicawtSpecResult<&mut T> {
        match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => Ok(v),
            Self::Bytes(b, v) => {
                let value = T::from_cbor_bytes(b)?;
                v.replace(value);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(v.as_mut().unwrap())
            }
        }
    }

    pub fn to_bytes(&mut self) -> EsdicawtSpecResult<&[u8]> {
        match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => Ok(b),
            Self::Value(v, b) => {
                let bytes = v.to_cbor_bytes()?;
                b.replace(bytes);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok(b.as_ref().unwrap())
            }
        }
    }

    pub fn clone_bytes(&self) -> EsdicawtSpecResult<Vec<u8>> {
        Ok(match self {
            Self::Bytes(b, _) | Self::Value(_, Some(b)) => b.clone(),
            Self::Value(v, _) => v.to_cbor_bytes()?,
        })
    }

    pub fn to_pair_mut(&mut self) -> EsdicawtSpecResult<(&mut T, &[u8])> {
        match self {
            Self::Value(v, Some(b)) | Self::Bytes(b, Some(v)) => Ok((v, b)),
            Self::Value(v, b) => {
                let bytes = v.to_cbor_bytes()?;
                b.replace(bytes);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok((v, b.as_ref().unwrap()))
            }
            Self::Bytes(b, v) => {
                let value = T::from_cbor_bytes(b)?;
                v.replace(value);
                // SAFETY: we just replaced the value so we can safely unwrap it
                Ok((v.as_mut().unwrap(), b))
            }
        }
    }

    // conflicting with `impl From<T>`
    pub fn from_bytes(b: Vec<u8>) -> Self {
        Self::Bytes(b, None)
    }

    pub fn try_into_value(self) -> EsdicawtSpecResult<T> {
        Ok(match self {
            Self::Value(v, _) | Self::Bytes(_, Some(v)) => v,
            Self::Bytes(b, _) => T::from_cbor_bytes(&b)?,
        })
    }
}

impl<T: CwtAny> From<T> for InlinedCbor<T> {
    fn from(v: T) -> Self {
        Self::Value(v, None)
    }
}
