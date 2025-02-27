use ciborium::Value;

#[derive(Debug, Clone, PartialEq)]
#[repr(transparent)]
pub struct Algorithm(coset::Algorithm);

impl From<coset::Algorithm> for Algorithm {
    fn from(v: coset::Algorithm) -> Self {
        Self(v)
    }
}

impl From<Algorithm> for coset::Algorithm {
    fn from(v: Algorithm) -> Self {
        v.0
    }
}

impl std::ops::Deref for Algorithm {
    type Target = coset::Algorithm;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl serde::Serialize for Algorithm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use coset::AsCborValue as _;
        use serde::ser::Error as _;

        serializer.serialize_some(&self.0.clone().to_cbor_value().map_err(S::Error::custom)?)
    }
}

impl<'de> serde::Deserialize<'de> for Algorithm {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let alg = <coset::Algorithm as coset::AsCborValue>::from_cbor_value(value).map_err(D::Error::custom)?;
        Ok(alg.into())
    }
}
