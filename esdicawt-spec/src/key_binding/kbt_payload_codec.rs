use super::KbtPayload;
use crate::{
    CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_NOT_BEFORE, CustomClaims, KbtStandardClaim, key_binding::KbtPayloadBuilder,
};
use ciborium::Value;
use serde::ser::SerializeMap;

impl<Extra: CustomClaims> serde::Serialize for KbtPayload<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry(&CWT_CLAIM_AUDIENCE, &self.audience)?;

        if let Some(expiration) = &self.expiration {
            map.serialize_entry(&CWT_CLAIM_EXPIRES_AT, expiration)?;
        }
        if let Some(not_before) = &self.not_before {
            map.serialize_entry(&CWT_CLAIM_NOT_BEFORE, not_before)?;
        }

        map.serialize_entry(&CWT_CLAIM_ISSUED_AT, &self.issued_at)?;

        if let Some(cnonce) = &self.cnonce {
            map.serialize_entry(&CWT_CLAIM_CNONCE, cnonce)?;
        }

        if let Some(extra) = &self.extra {
            for (k, v) in Value::serialized(extra)
                .map_err(S::Error::custom)?
                .into_map()
                .map_err(|_| S::Error::custom("should have been a mapping"))?
            {
                map.serialize_entry(&k, &v)?;
            }
        }

        map.end()
    }
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for KbtPayload<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SDPayloadVisitor<Extra: CustomClaims>(std::marker::PhantomData<Extra>);

        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SDPayloadVisitor<Extra> {
            type Value = KbtPayload<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a kbt-payload")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use ciborium::Value;
                use serde::de::Error as _;

                let mut extra = vec![];
                let mut sd_builder = KbtPayloadBuilder::<Extra>::default();

                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) => {
                            if let Ok(sd_claim_name) = KbtStandardClaim::try_from(label) {
                                match sd_claim_name {
                                    KbtStandardClaim::Audience => {
                                        sd_builder.audience(v.into_text().map_err(|value| A::Error::custom(format!("aud is not a string: {value:?}")))?);
                                    }
                                    KbtStandardClaim::ExpiresAt => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("exp is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("exp is not a 64-bit signed integer"))?;
                                        sd_builder.expiration(int);
                                    }
                                    KbtStandardClaim::NotBefore => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("nbf is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("nbf is not a 64-bit signed integer"))?;
                                        sd_builder.not_before(int);
                                    }
                                    KbtStandardClaim::IssuedAt => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("iat is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("iat is not a 64-bit signed integer"))?;
                                        sd_builder.issued_at(int);
                                    }
                                    KbtStandardClaim::Cnonce => {
                                        let cnonce: Vec<u8> = v.deserialized().map_err(|value| A::Error::custom(format!("cnonce is not bstr: {value:?}")))?;
                                        sd_builder.cnonce(cnonce);
                                    }
                                }
                            } else {
                                extra.push((k, v));
                            }
                        }
                        _ => {
                            extra.push((k, v));
                        }
                    };
                }

                if !extra.is_empty() {
                    let extra = Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?;
                    sd_builder.extra(extra);
                }

                sd_builder.build().map_err(|err| A::Error::custom(format!("{err}")))
            }
        }

        deserializer.deserialize_map(SDPayloadVisitor(Default::default()))
    }
}
