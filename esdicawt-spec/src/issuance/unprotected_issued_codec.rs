use ciborium::Value;
use serde::ser::SerializeMap;

use crate::{AnyMap, CustomClaims, MapKey, COSE_SD_CLAIMS};

use super::SdUnprotected;

impl<E: CustomClaims> serde::Serialize for SdUnprotected<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut extra: Option<AnyMap> = self.claims.clone().map(|extra| extra.into());
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

impl<'de, E: CustomClaims> serde::Deserialize<'de> for SdUnprotected<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnprotectedIssuedVisitor<E: CustomClaims>(std::marker::PhantomData<E>);

        impl<'de, E: CustomClaims> serde::de::Visitor<'de> for UnprotectedIssuedVisitor<E> {
            type Value = SdUnprotected<E>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an unprotected-issued header")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use serde::de::Error as _;
                let mut extra = AnyMap::default();
                let mut sd_claims = None;
                while let Some((k, v)) = map.next_entry::<MapKey, Value>()? {
                    if matches!(k, crate::ClaimName::Integer(COSE_SD_CLAIMS)) {
                        sd_claims.replace(v.deserialized().map_err(|err| A::Error::custom(format!("Cannot deserialize sd_claims: {err}")))?);
                    } else {
                        extra.insert(k, v);
                    }
                }

                let Some(sd_claims) = sd_claims else {
                    return Err(A::Error::custom("Missing sd_claims"));
                };

                Ok(SdUnprotected {
                    sd_claims,
                    claims: if extra.is_empty() {
                        None
                    } else {
                        Some(extra.try_into().map_err(|_err| A::Error::custom("Cannot deserialize CustomKeys".to_string()))?)
                    },
                })
            }
        }

        deserializer.deserialize_map(UnprotectedIssuedVisitor::<E>(Default::default()))
    }
}
