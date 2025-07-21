use crate::CoseKeyError;
use ciborium::Value;

#[allow(dead_code)]
pub trait CwtAny: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone {
    fn to_cbor_bytes(&self) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
        let mut buf = vec![];
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, ciborium::de::Error<std::io::Error>>
    where
        Self: Sized,
    {
        ciborium::from_reader(bytes)
    }

    fn to_cbor_value(&self) -> Result<Value, CoseKeyError> {
        Ok(Value::serialized(self)?)
    }

    fn from_cbor_value(value: &Value) -> Result<Self, CoseKeyError> {
        Ok(value.deserialized::<Self>()?)
    }
}

impl<T> CwtAny for T where T: serde::Serialize + for<'de> serde::Deserialize<'de> + Clone {}
