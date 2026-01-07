use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{COSE_HEADER_SD_CLAIMS, CustomClaims};

use super::SdUnprotected;

impl<Extra: CustomClaims> serde::Serialize for SdUnprotected<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;
        let extras = self
            .extra
            .as_ref()
            .map(Extra::to_cbor_value)
            .transpose()
            .map_err(S::Error::custom)?
            .map(Value::into_map)
            .transpose()
            .map_err(|e| S::Error::custom(format!("{e:?} should have been a mapping")))?
            .unwrap_or_default();

        let map_size = self.sd_claims.as_ref().map(|_| 1).unwrap_or_default() + extras.len();

        let mut map = serializer.serialize_map(Some(map_size))?;

        if let Some(sd_claims) = &self.sd_claims {
            map.serialize_entry(&COSE_HEADER_SD_CLAIMS, sd_claims)?;
        }

        for (k, v) in extras {
            map.serialize_entry(&k, &v)?;
        }
        map.end()
    }
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for SdUnprotected<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdUnprotectedVisitor<Extra: CustomClaims>(std::marker::PhantomData<Extra>);

        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SdUnprotectedVisitor<Extra> {
            type Value = SdUnprotected<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an unprotected-issued header")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let mut extra = vec![];
                let mut sd_claims = None;
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    if matches!(k, Value::Integer(label) if label == COSE_HEADER_SD_CLAIMS.into()) {
                        let salted_array = v.deserialized().map_err(|err| A::Error::custom(format!("Cannot deserialize sd_claims: {err}")))?;
                        sd_claims.replace(salted_array);
                    } else {
                        extra.push((k, v));
                    }
                }

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };
                Ok(SdUnprotected { sd_claims, extra })
            }
        }

        deserializer.deserialize_map(SdUnprotectedVisitor::<Extra>(Default::default()))
    }
}
