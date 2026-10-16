use super::{IatOrCti, KbtPayload};
use crate::{CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_NOT_BEFORE, CustomClaims, KbtStandardClaim};
use serde::ser::SerializeMap;

impl<Extra: CustomClaims> serde::Serialize for KbtPayload<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let extras = self
            .extra
            .as_ref()
            .map(|e| e.to_cbor_value())
            .transpose()
            .map_err(S::Error::custom)?
            .map(|v| v.into_map())
            .transpose()
            .map_err(|_| S::Error::custom("SD-KBT payload extras should have been a mapping"))?
            .unwrap_or_default();

        let map_size = 1 + // audience
            self.expiration.map(|_| 1).unwrap_or_default() +
            self.not_before.map(|_| 1).unwrap_or_default() +
            self.iat_or_cti.iat().map(|_| 1).unwrap_or_default() +
            self.iat_or_cti.cti().map(|_| 1).unwrap_or_default() +
            self.cnonce.as_ref().map(|_| 1).unwrap_or_default() + extras.len();
        let mut map = serializer.serialize_map(Some(map_size))?;

        map.serialize_entry(&CWT_CLAIM_AUDIENCE, &self.audience)?;

        if let Some(expiration) = &self.expiration {
            map.serialize_entry(&CWT_CLAIM_EXPIRES_AT, expiration)?;
        }
        if let Some(not_before) = &self.not_before {
            map.serialize_entry(&CWT_CLAIM_NOT_BEFORE, not_before)?;
        }

        if let Some(iat) = self.iat_or_cti.iat() {
            map.serialize_entry(&CWT_CLAIM_ISSUED_AT, &iat)?;
        }
        if let Some(cti) = self.iat_or_cti.cti() {
            map.serialize_entry(&CWT_CLAIM_CTI, serde_bytes::Bytes::new(cti))?;
        }

        if let Some(cnonce) = &self.cnonce {
            map.serialize_entry(&CWT_CLAIM_CNONCE, cnonce)?;
        }

        for (k, v) in extras {
            map.serialize_entry(&k, &v)?;
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

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use ciborium::Value;
                use serde::de::Error as _;

                let mut extra = vec![];
                let (mut audience, mut expiration, mut not_before, mut issued_at, mut cti, mut cnonce) = (None, None, None, None, None, None);

                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match k {
                        Value::Integer(label) => {
                            if let Ok(sd_claim_name) = KbtStandardClaim::try_from(label) {
                                match sd_claim_name {
                                    KbtStandardClaim::Audience => {
                                        audience = Some(v.into_text().map_err(|value| A::Error::custom(format!("aud is not a string: {value:?}")))?);
                                    }
                                    KbtStandardClaim::ExpiresAt => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("exp is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("exp is not a 64-bit signed integer"))?;
                                        expiration = Some(int);
                                    }
                                    KbtStandardClaim::NotBefore => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("nbf is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("nbf is not a 64-bit signed integer"))?;
                                        not_before = Some(int);
                                    }
                                    KbtStandardClaim::IssuedAt => {
                                        let cbor_int = v.into_integer().map_err(|value| A::Error::custom(format!("iat is not an integer: {value:?}")))?;
                                        let int: i64 = cbor_int.try_into().map_err(|_| A::Error::custom("iat is not a 64-bit signed integer"))?;
                                        issued_at = Some(int);
                                    }
                                    KbtStandardClaim::Cti => {
                                        cti = Some(
                                            v.deserialized::<serde_bytes::ByteBuf>()
                                                .map_err(|value| A::Error::custom(format!("cti is not bstr: {value:?}")))?,
                                        );
                                    }
                                    KbtStandardClaim::Cnonce => {
                                        let bytes = v
                                            .deserialized::<serde_bytes::ByteBuf>()
                                            .map_err(|value| A::Error::custom(format!("cnonce is not bstr: {value:?}")))?;
                                        cnonce = Some(bytes);
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

                let extra = if extra.is_empty() {
                    None
                } else {
                    Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(A::Error::custom)?)
                };

                // see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-kbt-and-sd-cwt-verifier-val (step 7)
                let iat_or_cti = match (issued_at, cti) {
                    (Some(iat), None) => IatOrCti::Iat(iat),
                    (Some(iat), Some(cti)) => IatOrCti::Both { iat, cti },
                    (None, Some(_)) if expiration.is_some() || not_before.is_some() => {
                        return Err(A::Error::custom("SD-KBT without 'iat' must not contain 'exp' nor 'nbf'"));
                    }
                    (None, Some(cti)) => IatOrCti::Cti(cti),
                    (None, None) => return Err(A::Error::custom("SD-KBT must contain either 'iat' or 'cti'")),
                };

                Ok(KbtPayload {
                    // see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-creating-a-key-binding-toke
                    audience: crate::required(audience, "aud")?,
                    expiration,
                    not_before,
                    iat_or_cti,
                    cnonce,
                    extra,
                })
            }
        }

        deserializer.deserialize_map(SDPayloadVisitor(Default::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CwtAny, NoClaims};
    use ciborium::{Value, cbor};

    fn decode(payload: Value) -> Result<KbtPayload<NoClaims>, crate::EsdicawtSpecError> {
        KbtPayload::from_cbor_bytes(&payload.to_cbor_bytes()?)
    }

    #[test]
    fn should_require_aud() {
        let (aud, iat) = (CWT_CLAIM_AUDIENCE, CWT_CLAIM_ISSUED_AT);
        let err = decode(cbor!({ iat => 10 }).unwrap()).unwrap_err();
        assert!(err.to_string().contains("`aud` must be initialized"), "{err}");
        // an empty one is still present
        assert_eq!(decode(cbor!({ aud => "", iat => 10 }).unwrap()).unwrap().audience, "");
    }

    #[test]
    fn should_verify_iat_or_cti() {
        let (aud, exp, nbf, iat, cti) = (CWT_CLAIM_AUDIENCE, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_NOT_BEFORE, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_CTI);
        let cti_value = Value::Bytes(b"kbt-id".to_vec());

        let with_iat = decode(cbor!({ aud => "a", iat => 10, exp => 20, nbf => 5 }).unwrap()).unwrap();
        assert_eq!(with_iat.iat_or_cti, IatOrCti::Iat(10));

        let with_cti = decode(cbor!({ aud => "a", cti => cti_value }).unwrap()).unwrap();
        assert_eq!(with_cti.iat_or_cti, IatOrCti::Cti(b"kbt-id".to_vec().into()));
        // round trip
        assert_eq!(KbtPayload::<NoClaims>::from_cbor_bytes(&with_cti.to_cbor_bytes().unwrap()).unwrap(), with_cti);

        let with_both = decode(cbor!({ aud => "a", iat => 10, cti => cti_value }).unwrap()).unwrap();
        assert_eq!(
            with_both.iat_or_cti,
            IatOrCti::Both {
                iat: 10,
                cti: b"kbt-id".to_vec().into()
            }
        );

        assert!(decode(cbor!({ aud => "a" }).unwrap()).is_err());
        assert!(decode(cbor!({ aud => "a", cti => cti_value, exp => 20 }).unwrap()).is_err());
        assert!(decode(cbor!({ aud => "a", cti => cti_value, nbf => 5 }).unwrap()).is_err());
        assert!(decode(cbor!({ aud => "a", cti => "not-bstr" }).unwrap()).is_err());
    }
}
