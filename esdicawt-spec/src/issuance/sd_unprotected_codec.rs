use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{COSE_SD_CLAIMS, CustomClaims};

use super::SdUnprotected;

impl<Extra: CustomClaims> serde::Serialize for SdUnprotected<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut extra = self
            .extra
            .as_ref()
            .map(|extra| extra.to_cbor_value().map_err(S::Error::custom))
            .transpose()?
            .map(|v| v.into_map().map_err(|_| S::Error::custom("should have been a mapping")))
            .transpose()?;
        let extra_len = extra.as_ref().map(|extra| extra.len()).unwrap_or_default();

        let mut map = serializer.serialize_map(Some(1 + extra_len))?;

        map.serialize_entry(&COSE_SD_CLAIMS, &self.sd_claims)?;

        if let Some(extra) = extra.take() {
            for (k, v) in extra {
                map.serialize_entry(&k, &v)?;
            }
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
                    if matches!(k, Value::Integer(label) if label == COSE_SD_CLAIMS.into()) {
                        let salted_array = v.deserialized().map_err(|err| A::Error::custom(format!("Cannot deserialize sd_claims: {err}")))?;
                        sd_claims.replace(salted_array);
                    } else {
                        extra.push((k, v));
                    }
                }

                let Some(sd_claims) = sd_claims else {
                    return Err(A::Error::custom("Missing sd_claims"));
                };

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
