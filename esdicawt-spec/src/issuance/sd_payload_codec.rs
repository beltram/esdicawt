use crate::{
    AnyMap, CWT_CLAIM_AUDIENCE, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION_MAP, CWT_CLAIM_NOT_BEFORE, CWT_CLAIM_SUBJECT, ClaimName,
    CustomClaims, MapKey, SelectiveDisclosureStandardClaim,
    issuance::{SdInnerPayload, SdInnerPayloadBuilder, SdPayload, SdPayloadBuilder},
    redacted_claims::RedactedClaimKeys,
};
use ciborium::Value;

use cose_key_confirmation::KeyConfirmation;
use serde::ser::SerializeMap;

impl<Extra: CustomClaims> serde::Serialize for SdPayload<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;

        serialize_sd_cwt_payload::<Extra, S>(&self.inner, &mut map)?;

        map.serialize_entry(&CWT_CLAIM_KEY_CONFIRMATION_MAP, &self.cnf)?;

        if let Some(redacted_claim_keys) = &self.redacted_claim_keys {
            let label = Value::Simple(RedactedClaimKeys::CWT_LABEL);
            map.serialize_entry(&label, redacted_claim_keys)?;
        }

        map.end()
    }
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for SdPayload<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SelectiveDisclosurePayloadVisitor<E>(std::marker::PhantomData<E>);

        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SelectiveDisclosurePayloadVisitor<Extra> {
            type Value = SdPayload<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an issuer sd-payload")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use ciborium::Value;
                use serde::de::Error as _;

                let mut extra = vec![];
                let mut builder = SdPayloadBuilder::<Extra>::default();

                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    let label = k.deserialized::<ClaimName>().map_err(A::Error::custom)?;
                    match label {
                        ClaimName::Integer(key) => match SelectiveDisclosureStandardClaim::try_from(key) {
                            Ok(SelectiveDisclosureStandardClaim::KeyConfirmationClaim) => {
                                let kc: KeyConfirmation = v.deserialized().map_err(|value| A::Error::custom(format!("cnf is not a map: {value:?}")))?;
                                builder.cnf(kc);
                            }
                            _ => {
                                extra.push((k, v));
                            }
                        },
                        ClaimName::SimpleValue(label) if label == RedactedClaimKeys::CWT_LABEL => {
                            let redacted_claim_keys = v
                                .deserialized::<RedactedClaimKeys>()
                                .map_err(|value| A::Error::custom(format!("redacted_claim_keys is not an array: {value:?}")))?;
                            builder.redacted_claim_keys(redacted_claim_keys);
                        }
                        _ => {
                            extra.push((k, v));
                        }
                    };
                }

                let extra = Value::Map(extra);
                let inner = extra.deserialized::<SdInnerPayload<Extra>>().map_err(A::Error::custom)?;

                builder.inner(inner).build().map_err(A::Error::custom)
            }
        }

        deserializer.deserialize_map(SelectiveDisclosurePayloadVisitor(Default::default()))
    }
}

impl<Extra: CustomClaims> serde::Serialize for SdInnerPayload<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        serialize_sd_cwt_payload::<Extra, S>(self, &mut map)?;
        map.end()
    }
}

fn serialize_sd_cwt_payload<Extra: CustomClaims, S: serde::Serializer>(p: &SdInnerPayload<Extra>, map: &mut S::SerializeMap) -> Result<(), S::Error> {
    map.serialize_entry(&CWT_CLAIM_ISSUER, &p.issuer)?;
    if let Some(sub) = &p.subject {
        map.serialize_entry(&CWT_CLAIM_SUBJECT, sub)?;
    }
    if let Some(audience) = &p.audience {
        map.serialize_entry(&CWT_CLAIM_AUDIENCE, &audience)?;
    }
    if let Some(expiration) = &p.expiration {
        map.serialize_entry(&CWT_CLAIM_EXPIRES_AT, expiration)?;
    }
    if let Some(not_before) = &p.not_before {
        map.serialize_entry(&CWT_CLAIM_NOT_BEFORE, not_before)?;
    }
    if let Some(iat) = &p.issued_at {
        map.serialize_entry(&CWT_CLAIM_ISSUED_AT, iat)?;
    }

    if let Some(extra) = &p.extra {
        let extra_map: AnyMap = extra.clone().into();
        for (k, v) in extra_map {
            map.serialize_entry(&k, &v)?;
        }
    }
    Ok(())
}

impl<'de, Extra: CustomClaims> serde::Deserialize<'de> for SdInnerPayload<Extra> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SdCwtPayloadVisitor<E>(std::marker::PhantomData<E>);

        impl<'de, Extra: CustomClaims> serde::de::Visitor<'de> for SdCwtPayloadVisitor<Extra> {
            type Value = SdInnerPayload<Extra>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an issuer sd-payload")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use ciborium::Value;
                use serde::de::Error as _;

                let mut extra = AnyMap::default();
                let mut builder = SdInnerPayloadBuilder::<Extra>::default();

                while let Some((k, v)) = map.next_entry::<MapKey, Value>()? {
                    match k {
                        ClaimName::Integer(key) => match SelectiveDisclosureStandardClaim::try_from(key) {
                            Ok(SelectiveDisclosureStandardClaim::IssuerClaim) => {
                                builder.issuer(v.into_text().map_err(|value| A::Error::custom(format!("iss is not a string: {value:?}")))?);
                            }
                            Ok(SelectiveDisclosureStandardClaim::SubjectClaim) => {
                                builder.subject(v.into_text().map_err(|value| A::Error::custom(format!("sub is not a string: {value:?}")))?);
                            }
                            Ok(SelectiveDisclosureStandardClaim::AudienceClaim) => {
                                builder.audience(v.into_text().map_err(|value| A::Error::custom(format!("aud is not a string: {value:?}")))?);
                            }
                            Ok(SelectiveDisclosureStandardClaim::ExpiresAtClaim) => {
                                let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("exp is not an integer: {value:?}")))?;
                                let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("exp is not a 64-bit signed integer"))?;
                                builder.expiration(int);
                            }
                            Ok(SelectiveDisclosureStandardClaim::NotBeforeClaim) => {
                                let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("nbf is not an integer: {value:?}")))?;
                                let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("nbf is not a 64-bit signed integer"))?;
                                builder.not_before(int);
                            }
                            Ok(SelectiveDisclosureStandardClaim::IssuedAtClaim) => {
                                let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("iat is not an integer: {value:?}")))?;
                                let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("iat is not a 64-bit signed integer"))?;
                                builder.issued_at(int);
                            }
                            _ => {
                                extra.insert(k, v);
                            }
                        },
                        _ => {
                            extra.insert(k, v);
                        }
                    };
                }

                if !extra.is_empty() {
                    let custom_keys: Extra = extra.try_into().map_err(|_err| A::Error::custom("Cannot deserialize custom keys".to_string()))?;
                    builder.extra(custom_keys);
                }

                builder.build().map_err(A::Error::custom)
            }
        }

        deserializer.deserialize_map(SdCwtPayloadVisitor(Default::default()))
    }
}
