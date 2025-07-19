use crate::{
    CborAny, StatusList,
    issuer::{
        StatusListToken, StatusListTokenBuilder,
        cose::{LABEL_TYPE, MEDIATYPE_STATUS_LIST_CWT},
    },
};
use ciborium::Value;
use coset::{
    AsCborValue, CborSerializable, TaggedCborSerializable,
    cwt::{ClaimName, Timestamp},
    iana::CwtClaimName,
};

impl serde::Serialize for StatusListToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let protected = coset::HeaderBuilder::new().value(LABEL_TYPE, Value::Text(MEDIATYPE_STATUS_LIST_CWT.to_string())).build();

        let unprotected = coset::HeaderBuilder::new().build();

        let lst = self
            .status_list
            .to_cbor_bytes()
            .map_err(|e| S::Error::custom(format!("Could not serialize status list because {e:?}")))?;

        let mut payload = coset::cwt::ClaimsSetBuilder::new()
            .subject(self.sub.to_string())
            .issued_at(Timestamp::WholeSeconds(self.iat as i64))
            .claim(CwtClaimName::StatusList, Value::Bytes(lst));

        if let Some(exp) = self.exp {
            payload = payload.expiration_time(Timestamp::WholeSeconds(exp as i64));
        }

        if let Some(ttl) = self.ttl {
            payload = payload.claim(CwtClaimName::Ttl, Timestamp::WholeSeconds(ttl as i64).to_cbor_value().map_err(S::Error::custom)?)
        }

        let payload = payload.build().to_vec().map_err(S::Error::custom)?;

        let cbor_bytes = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload)
            .signature(self.signature.to_vec())
            .build()
            .to_tagged_vec()
            .map_err(S::Error::custom)?;

        serializer.serialize_bytes(&cbor_bytes)
    }
}

impl<'de> serde::Deserialize<'de> for StatusListToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let mut builder = StatusListTokenBuilder::default();

        let value = <Vec<u8> as serde::Deserialize>::deserialize(deserializer)?;
        let sign1 = coset::CoseSign1::from_tagged_slice(&value).map_err(D::Error::custom)?;

        if let Some(payload) = &sign1.payload {
            let mut claim_set = coset::cwt::ClaimsSet::from_slice(payload).map_err(D::Error::custom)?;
            if let Some(sub) = &claim_set.subject {
                builder.sub(sub.parse().map_err(D::Error::custom)?);
            }
            if let Some(Timestamp::WholeSeconds(iat)) = &claim_set.issued_at {
                builder.iat((*iat).try_into().map_err(D::Error::custom)?);
            }
            if let Some(Timestamp::WholeSeconds(exp)) = &claim_set.expiration_time {
                builder.exp((*exp).try_into().map_err(D::Error::custom)?);
            }
            for v in claim_set.rest.drain(..) {
                match v {
                    (ClaimName::Assigned(CwtClaimName::Ttl), Value::Integer(ttl)) => {
                        builder.ttl(ttl.try_into().map_err(D::Error::custom)?);
                    }
                    (ClaimName::Assigned(CwtClaimName::StatusList), Value::Bytes(status_list)) => {
                        builder.status_list(StatusList::from_cbor_bytes(&status_list).map_err(D::Error::custom)?);
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
    use crate::{Lst, StatusBits, StatusList};

    #[test]
    fn should_roundtrip() {
        let input = StatusListToken {
            sub: "https://sub.com".parse().unwrap(),
            iat: 40,
            exp: Some(41),
            ttl: Some(42),
            status_list: StatusList {
                bits: StatusBits::One,
                lst: Lst::new(vec![0xB9, 0xA3], StatusBits::One),
                aggregation_uri: Some("https://agg.com".parse().unwrap()),
            },
            signature: b"signature".to_vec().into(),
        };

        let ser = input.to_cbor_bytes().unwrap();
        let output = StatusListToken::from_cbor_bytes(&ser).unwrap();

        assert_eq!(input, output);
    }
}
