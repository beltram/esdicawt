use super::KeyBindingTokenPayload;
use crate::{
    AnyMap, CWT_CLAIM_AUDIENCE, CWT_CLAIM_CLIENT_NONCE, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_NOT_BEFORE, ClaimName, CustomClaims, KbtStandardClaim, MapKey,
    key_binding::KeyBindingTokenPayloadBuilder,
};
use serde::ser::SerializeMap;

impl<E: CustomClaims> serde::Serialize for KeyBindingTokenPayload<E> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;

        map.serialize_entry(&CWT_CLAIM_AUDIENCE, &self.audience)?;

        if let Some(expiration) = &self.expiration {
            map.serialize_entry(&CWT_CLAIM_EXPIRES_AT, expiration)?;
        }
        if let Some(not_before) = &self.not_before {
            map.serialize_entry(&CWT_CLAIM_NOT_BEFORE, not_before)?;
        }

        map.serialize_entry(&CWT_CLAIM_ISSUED_AT, &self.issued_at)?;

        if let Some(cnonce) = &self.client_nonce {
            map.serialize_entry(&CWT_CLAIM_CLIENT_NONCE, cnonce)?;
        }

        if let Some(extra) = &self.claims {
            let extra_map: AnyMap = extra.clone().into();

            for (k, v) in extra_map {
                map.serialize_entry(&k, &v)?;
            }
        }

        map.end()
    }
}

impl<'de, E: CustomClaims> serde::Deserialize<'de> for KeyBindingTokenPayload<E> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SDPayloadVisitor<E: CustomClaims>(std::marker::PhantomData<E>);

        impl<'de, E: CustomClaims> serde::de::Visitor<'de> for SDPayloadVisitor<E> {
            type Value = KeyBindingTokenPayload<E>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a kbt-payload")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                use ciborium::Value;
                use serde::de::Error as _;

                let mut extra = AnyMap::default();
                let mut sd_builder = KeyBindingTokenPayloadBuilder::<E>::default();

                while let Some((k, v)) = map.next_entry::<MapKey, Value>()? {
                    match k {
                        ClaimName::Integer(claim_value) => {
                            if let Ok(sd_claim_name) = KbtStandardClaim::try_from(claim_value) {
                                match sd_claim_name {
                                    KbtStandardClaim::AudienceClaim => {
                                        sd_builder.audience(v.into_text().map_err(|value| A::Error::custom(format!("aud is not a string: {value:?}")))?);
                                    }
                                    KbtStandardClaim::ExpiresAtClaim => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("exp is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("exp is not a 64-bit signed integer"))?;
                                        sd_builder.expiration(int);
                                    }
                                    KbtStandardClaim::NotBeforeClaim => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("nbf is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("nbf is not a 64-bit signed integer"))?;
                                        sd_builder.not_before(int);
                                    }
                                    KbtStandardClaim::IssuedAtClaim => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("iat is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("iat is not a 64-bit signed integer"))?;
                                        sd_builder.issued_at(int);
                                    }
                                    KbtStandardClaim::ClientNonceClaim => {
                                        let cnonce: Vec<u8> = v.deserialized().map_err(|value| A::Error::custom(format!("cnonce is not bstr: {value:?}")))?;
                                        sd_builder.client_nonce(cnonce);
                                    }
                                }
                            } else {
                                extra.insert(k, v);
                            }
                        }
                        _ => {
                            extra.insert(k, v);
                        }
                    };
                }

                if !extra.is_empty() {
                    let custom_keys: E = extra.try_into().map_err(|_err| A::Error::custom("Cannot deserialize custom keys".to_string()))?;
                    sd_builder.claims(custom_keys);
                }

                sd_builder.build().map_err(|err| A::Error::custom(format!("{err}")))
            }
        }

        deserializer.deserialize_map(SDPayloadVisitor(Default::default()))
    }
}
