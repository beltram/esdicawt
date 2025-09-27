use crate::{
    CborAny, Status, StatusList,
    issuer::{
        StatusListToken, StatusListTokenBuilder,
        cose::{LABEL_TYPE, MEDIATYPE_STATUS_LIST_CWT},
    },
};
use ciborium::Value;
use coset::{
    Algorithm, AsCborValue, CborSerializable, TaggedCborSerializable,
    cwt::{ClaimName, Timestamp},
    iana::CwtClaimName,
};

impl<St: Status> serde::Serialize for StatusListToken<St> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let mut protected_builder = coset::HeaderBuilder::new();
        if let Some(alg) = self.alg {
            protected_builder = protected_builder.algorithm(alg);
        }
        let protected = protected_builder.value(LABEL_TYPE, Value::Text(MEDIATYPE_STATUS_LIST_CWT.to_string())).build();

        let mut unprotected_builder = coset::HeaderBuilder::new();
        if let Some(kid) = self.key_id.clone() {
            unprotected_builder = unprotected_builder.key_id(kid);
        }
        let unprotected = unprotected_builder.build();

        let status_list = self
            .status_list
            .to_cbor_value()
            .map_err(|e| S::Error::custom(format!("Could not serialize status list because {e:?}")))?;

        let mut payload = coset::cwt::ClaimsSetBuilder::new()
            .subject(self.sub.to_string())
            .issued_at(Timestamp::WholeSeconds(self.iat))
            .claim(CwtClaimName::StatusList, status_list);

        if let Some(exp) = self.exp {
            payload = payload.expiration_time(Timestamp::WholeSeconds(exp));
        }

        if let Some(ttl) = self.ttl {
            payload = payload.claim(CwtClaimName::Ttl, Timestamp::WholeSeconds(ttl as i64).to_cbor_value().map_err(S::Error::custom)?)
        }

        let payload = payload.build().to_vec().map_err(S::Error::custom)?;

        let value = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .signature(self.signature.to_vec())
            .build()
            .to_cbor_value()
            .map_err(S::Error::custom)?;

        ciborium::tag::Required::<_, { <coset::CoseSign1 as TaggedCborSerializable>::TAG }>(value).serialize(serializer)
    }
}

impl<'de, S: Status> serde::Deserialize<'de> for StatusListToken<S> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let mut builder = StatusListTokenBuilder::default();

        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        let Value::Tag(<coset::CoseSign1 as TaggedCborSerializable>::TAG, value) = value else {
            unreachable!()
        };
        let sign1 = coset::CoseSign1::from_cbor_value(*value).map_err(D::Error::custom)?;

        sign1.protected.header.alg.inspect(|alg| {
            if let Algorithm::Assigned(alg) = alg {
                builder.alg(*alg);
            }
        });

        if !sign1.unprotected.key_id.is_empty() {
            builder.key_id(sign1.unprotected.key_id);
        }

        if let Some(payload) = &sign1.payload {
            let mut claim_set = coset::cwt::ClaimsSet::from_slice(payload).map_err(D::Error::custom)?;
            if let Some(sub) = &claim_set.subject {
                builder.sub(sub.parse().map_err(D::Error::custom)?);
            }
            if let Some(Timestamp::WholeSeconds(iat)) = &claim_set.issued_at {
                builder.iat(*iat);
            }
            if let Some(Timestamp::WholeSeconds(exp)) = &claim_set.expiration_time {
                builder.exp(*exp);
            }
            for v in claim_set.rest.drain(..) {
                match v {
                    (ClaimName::Assigned(CwtClaimName::Ttl), Value::Integer(ttl)) => {
                        builder.ttl(ttl.try_into().map_err(D::Error::custom)?);
                    }
                    (ClaimName::Assigned(CwtClaimName::StatusList), value) => {
                        let status_list = StatusList::<S>::from_cbor_value(&value).map_err(D::Error::custom)?;
                        builder.status_list(status_list);
                    }
                    _ => {}
                }
            }
        }
        builder.signature(sign1.signature.into());

        builder.build().map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RawStatus, StatusList};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_roundtrip() {
        let status_list = StatusList::<RawStatus<1>>::from_slice(&[0xB9, 0xA3], Some("https://agg.com".parse().unwrap()));
        let input = StatusListToken {
            alg: Some(coset::iana::Algorithm::EdDSA),
            key_id: None,
            sub: "https://sub.com".parse().unwrap(),
            iat: 40,
            exp: Some(41),
            ttl: Some(42),
            status_list,
            signature: b"signature".to_vec().into(),
        };

        let ser = input.to_cbor_bytes().unwrap();

        coset::CoseSign1::from_tagged_slice(&ser).unwrap();

        let output = StatusListToken::from_cbor_bytes(&ser).unwrap();
        assert_eq!(input, output);
    }
}
