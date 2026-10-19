use crate::{
    CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION, CWT_CLAIM_NOT_BEFORE,
    CWT_CLAIM_SUBJECT, CustomClaims, SdCwtClaim, SdCwtStandardClaim,
    issuance::{SdInnerPayload, SdPayload},
    redacted_claims::RedactedClaimKeys,
};
use ciborium::Value;
use cose_key::confirmation::KeyConfirmation;
use serde::ser::SerializeMap;

impl<Extra: CustomClaims> serde::Serialize for SdPayload<Extra> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let extras = self
            .inner
            .extra
            .as_ref()
            .map(|e| e.to_cbor_value())
            .transpose()
            .map_err(S::Error::custom)?
            .map(|v| v.into_map())
            .transpose()
            .map_err(|_| S::Error::custom("should have been a mapping"))?
            .unwrap_or_default();

        #[allow(unused_mut)]
        let mut map_size = 1 + // cnf
            sd_cwt_payload_map_size(&self.inner) +
            extras.len() +
            self.redacted_claim_keys.as_ref().map(|_| 1).unwrap_or_default();

        if cfg!(feature = "status") {
            map_size += 1;
        }

        let mut map = serializer.serialize_map(Some(map_size))?;

        serialize_sd_cwt_payload::<Extra, S>(&self.inner, extras, &mut map)?;

        map.serialize_entry(&CWT_CLAIM_KEY_CONFIRMATION, &self.cnf)?;
        #[cfg(feature = "status")]
        {
            use coset::iana::EnumI64 as _;
            map.serialize_entry(&coset::iana::CwtClaimName::Status.to_i64(), &self.inner.status)?;
        }

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
                use serde::de::Error as _;

                let mut extra = vec![];
                let (mut cnf, mut redacted_claim_keys) = (None, None);

                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    let label = k.deserialized::<SdCwtClaim>().map_err(A::Error::custom)?;
                    match label {
                        SdCwtClaim::Int(key) => match SdCwtStandardClaim::try_from(key) {
                            Ok(SdCwtStandardClaim::KeyConfirmation) => {
                                let kc = v
                                    .deserialized::<KeyConfirmation>()
                                    .map_err(|value| A::Error::custom(format!("cnf is not a map: {value:?}")))?;
                                cnf = Some(kc);
                            }
                            _ => {
                                extra.push((k, v));
                            }
                        },
                        SdCwtClaim::SimpleValue(label) if label == RedactedClaimKeys::CWT_LABEL => {
                            let rcks = v
                                .deserialized::<RedactedClaimKeys>()
                                .map_err(|value| A::Error::custom(format!("redacted_claim_keys is not an array: {value:?}")))?;
                            redacted_claim_keys = Some(rcks);
                        }
                        _ => {
                            extra.push((k, v));
                        }
                    };
                }

                // decoded as a ciborium error to keep the same error messages as when it was deserialized from a `Value`
                let mut extra = extra.into_iter();
                let inner = decode_sd_inner_payload::<Extra, ciborium::value::Error>(|| Ok(extra.next())).map_err(A::Error::custom)?;

                Ok(SdPayload {
                    cnf: crate::required(cnf, "cnf")?,
                    redacted_claim_keys,
                    inner,
                })
            }
        }

        deserializer.deserialize_map(SelectiveDisclosurePayloadVisitor(Default::default()))
    }
}

impl<Extra: CustomClaims> serde::Serialize for SdInnerPayload<Extra> {
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
            .map_err(|_| S::Error::custom("should have been a mapping"))?
            .unwrap_or_default();

        let mut map = serializer.serialize_map(None)?;
        serialize_sd_cwt_payload::<Extra, S>(self, extras, &mut map)?;
        map.end()
    }
}

fn sd_cwt_payload_map_size<Extra: CustomClaims>(p: &SdInnerPayload<Extra>) -> usize {
    1 + // issuer
        p.subject.as_ref().map(|_| 1).unwrap_or_default() +
        p.audience.as_ref().map(|_| 1).unwrap_or_default() +
        p.expiration.map(|_| 1).unwrap_or_default() +
        p.not_before.map(|_| 1).unwrap_or_default() +
        p.issued_at.map(|_| 1).unwrap_or_default() +
        p.cti.as_ref().map(|_| 1).unwrap_or_default() +
        p.cnonce.as_ref().map(|_| 1).unwrap_or_default()
}

fn serialize_sd_cwt_payload<Extra: CustomClaims, S: serde::Serializer>(p: &SdInnerPayload<Extra>, extras: Vec<(Value, Value)>, map: &mut S::SerializeMap) -> Result<(), S::Error> {
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
    if let Some(cti) = &p.cti {
        map.serialize_entry(&CWT_CLAIM_CTI, cti)?;
    }
    if let Some(cnonce) = &p.cnonce {
        map.serialize_entry(&CWT_CLAIM_CNONCE, cnonce)?;
    }

    for (k, v) in extras {
        map.serialize_entry(&k, &v)?;
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
                decode_sd_inner_payload(|| map.next_entry::<Value, Value>())
            }
        }

        deserializer.deserialize_map(SdCwtPayloadVisitor(Default::default()))
    }
}

/// Builds the payload from its entries
fn decode_sd_inner_payload<Extra: CustomClaims, E: serde::de::Error>(mut next_entry: impl FnMut() -> Result<Option<(Value, Value)>, E>) -> Result<SdInnerPayload<Extra>, E> {
    let (mut issuer, mut subject, mut audience, mut expiration, mut not_before, mut issued_at, mut cti, mut cnonce) = (None, None, None, None, None, None, None, None);
    #[cfg(feature = "status")]
    let mut status = None;
    let mut extra = vec![];

    while let Some((k, v)) = next_entry()? {
        match k {
            ref label @ Value::Integer(_) => match SdCwtStandardClaim::try_from(label) {
                Ok(SdCwtStandardClaim::Issuer) => {
                    issuer = Some(v.into_text().map_err(|value| E::custom(format!("iss is not a string: {value:?}")))?);
                }
                Ok(SdCwtStandardClaim::Subject) => {
                    subject = Some(v.into_text().map_err(|value| E::custom(format!("sub is not a string: {value:?}")))?);
                }
                Ok(SdCwtStandardClaim::Audience) => {
                    audience = Some(v.into_text().map_err(|value| E::custom(format!("aud is not a string: {value:?}")))?);
                }
                Ok(SdCwtStandardClaim::ExpiresAt) => {
                    let cbor_int = v.into_integer().map_err(|value| E::custom(format!("exp is not an integer: {value:?}")))?;
                    let int: i64 = cbor_int.try_into().map_err(|_| E::custom("exp is not a 64-bit signed integer"))?;
                    expiration = Some(int);
                }
                Ok(SdCwtStandardClaim::NotBefore) => {
                    let cbor_int = v.into_integer().map_err(|value| E::custom(format!("nbf is not an integer: {value:?}")))?;
                    let int: i64 = cbor_int.try_into().map_err(|_| E::custom("nbf is not a 64-bit signed integer"))?;
                    not_before = Some(int);
                }
                Ok(SdCwtStandardClaim::IssuedAt) => {
                    let cbor_int = v.into_integer().map_err(|value| E::custom(format!("iat is not an integer: {value:?}")))?;
                    let int: i64 = cbor_int.try_into().map_err(|_| E::custom("iat is not a 64-bit signed integer"))?;
                    issued_at = Some(int);
                }
                Ok(SdCwtStandardClaim::Cnonce) => {
                    let bytes = v.into_bytes().map_err(|value| E::custom(format!("cnonce is not a bstr: {value:?}")))?;
                    cnonce = Some(bytes.into());
                }
                Ok(SdCwtStandardClaim::Cti) => {
                    let bytes = v.into_bytes().map_err(|value| E::custom(format!("cti is not a bstr: {value:?}")))?;
                    cti = Some(bytes.into());
                }
                #[cfg(feature = "status")]
                Ok(SdCwtStandardClaim::Status) => {
                    status = Some(v.deserialized().map_err(E::custom)?);
                }
                _ => {
                    extra.push((k, v));
                }
            },
            Value::Text(_) | Value::Simple(_) => {
                extra.push((k, v));
            }
            // see https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-update-to-the-cbor-web-toke
            Value::Tag(_, ref value) if value.is_integer() || value.is_text() => {
                extra.push((k, v));
            }
            _ => {
                return Err(E::custom("Deserializing invalid claim label"));
            }
        };
    }

    let extra = if extra.is_empty() {
        None
    } else {
        Some(Value::deserialized::<Extra>(&Value::Map(extra)).map_err(E::custom)?)
    };

    Ok(SdInnerPayload {
        issuer: crate::required(issuer, "issuer")?,
        subject,
        audience,
        expiration,
        not_before,
        issued_at,
        cti,
        cnonce,
        #[cfg(feature = "status")]
        status: crate::required(status, "status")?,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CwtAny, key_binding::KbtPayload};

    #[test]
    fn should_keep_null_claims() {
        // the required claims
        let payload = |claims: Vec<(Value, Value)>| {
            #[allow(unused_mut)]
            let mut payload = vec![(Value::from(CWT_CLAIM_ISSUER), Value::from("https://issuer.example"))];
            #[cfg(feature = "status")]
            payload.push((
                Value::from(crate::CWT_CLAIM_STATUS),
                status_list::StatusClaim::new(0, "https://example.com/statuslists/1".parse().unwrap())
                    .to_cbor_value()
                    .unwrap(),
            ));
            payload.extend(claims);
            Value::Map(payload).to_cbor_bytes().unwrap()
        };

        // a custom claim can be null
        let decoded = SdInnerPayload::<Value>::from_cbor_bytes(&payload(vec![(Value::from("nothing"), Value::Null)])).unwrap();
        assert_eq!(decoded.extra, Some(Value::Map(vec![(Value::from("nothing"), Value::Null)])));

        // but not a standard claim
        for claim in [CWT_CLAIM_ISSUER, CWT_CLAIM_SUBJECT, CWT_CLAIM_AUDIENCE, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_CTI] {
            let err = SdInnerPayload::<Value>::from_cbor_bytes(&payload(vec![(Value::from(claim), Value::Null)])).unwrap_err();
            assert!(err.to_string().contains("is not a"), "{claim}: {err}");
        }
    }

    #[test]
    fn missing_required_claims_should_fail() {
        let no_issuer = Value::Map(vec![(Value::from(CWT_CLAIM_SUBJECT), Value::from("subject"))]);
        let err = SdInnerPayload::<Value>::from_owned_cbor_value(no_issuer.clone()).unwrap_err();
        assert!(err.to_string().contains("`issuer` must be initialized"), "{err}");
        let err = SdInnerPayload::<Value>::from_cbor_bytes(&no_issuer.to_cbor_bytes().unwrap()).unwrap_err();
        assert!(err.to_string().contains("`issuer` must be initialized"), "{err}");

        // the inner payload is decoded first, as it was before
        let err = SdPayload::<Value>::from_cbor_bytes(&no_issuer.to_cbor_bytes().unwrap()).unwrap_err();
        assert!(err.to_string().contains("`issuer` must be initialized"), "{err}");
        #[cfg(not(feature = "status"))]
        {
            let no_cnf = Value::Map(vec![(Value::from(CWT_CLAIM_ISSUER), Value::from("https://issuer.example"))]);
            let err = SdPayload::<Value>::from_cbor_bytes(&no_cnf.to_cbor_bytes().unwrap()).unwrap_err();
            assert!(err.to_string().contains("`cnf` must be initialized"), "{err}");
        }

        let no_iat_nor_cti = Value::Map(vec![(Value::from(CWT_CLAIM_AUDIENCE), Value::from("aud"))]);
        let err = KbtPayload::<Value>::from_cbor_bytes(&no_iat_nor_cti.to_cbor_bytes().unwrap()).unwrap_err();
        assert!(err.to_string().contains("must contain either 'iat' or 'cti'"), "{err}");
    }
}
