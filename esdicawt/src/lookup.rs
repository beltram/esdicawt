#![allow(dead_code)]

use crate::spec::{
    ClaimName,
    blinded_claims::{Salted, SaltedArray},
};
use ciborium::Value;
use esdicawt_spec::{CustomClaims, CwtAny, EsdicawtSpecResult, REDACTED_CLAIM_ELEMENT_TAG, Select, issuance::SdCwtIssued, redacted_claims::RedactedClaimKeys};

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Query {
    pub elements: Vec<QueryElement>,
}

impl From<Vec<QueryElement>> for Query {
    fn from(elements: Vec<QueryElement>) -> Self {
        Self { elements }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
/// enum for claim queries, allowing for future ways to query the token
pub enum QueryElement {
    /// selects a claim key
    ClaimName(ClaimName),
    /// Selects an element in an array
    Index(usize),
}

impl From<&str> for QueryElement {
    fn from(s: &str) -> Self {
        Self::ClaimName(s.into())
    }
}

impl From<i64> for QueryElement {
    fn from(i: i64) -> Self {
        Self::ClaimName(i.into())
    }
}

impl From<usize> for QueryElement {
    fn from(i: usize) -> Self {
        Self::Index(i)
    }
}

pub fn query<Hasher>(array: &SaltedArray, payload: &Value, query: &[u8]) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest,
{
    let query: Query = ciborium::from_reader(&mut &*query)?;

    query_inner::<Hasher>(array, payload, &query.elements)
}

pub fn query_inner<Hasher>(array: &SaltedArray, payload: &Value, query: &[QueryElement]) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest,
{
    let value = match query.first() {
        Some(QueryElement::ClaimName(name)) => {
            let name_key = Value::serialized(name)?;
            let Some(map) = payload.as_map() else {
                return Ok(None);
            };

            // check the presence in the payload
            match map.iter().find_map(|(k, v)| if k == &name_key { Some(v.clone()) } else { None }) {
                Some(v) => v,
                None => {
                    // if not in the payload, we will look in the salted array
                    let rcks_key: Value = Value::Simple(RedactedClaimKeys::CWT_LABEL);
                    let Some(rcks) = map.iter().find_map(|(k, v)| if k == &rcks_key { Some(v) } else { None }).and_then(|v| v.as_array()) else {
                        return Ok(None);
                    };

                    let mut found = None;
                    for salted in array.iter().flatten() {
                        if let Salted::Claim(sc) = salted {
                            if sc.name == *name {
                                // if we found an element with a matching claim name, check that it is present in the payload's
                                // redacted claim keys list
                                let mut cbor = vec![];
                                ciborium::into_writer(&sc, &mut cbor)?;
                                let hashed: Value = Hasher::digest(cbor.clone()).to_vec().into();

                                if rcks.contains(&hashed) {
                                    found = Some(sc.value);
                                    break;
                                }
                            }
                        }
                    }

                    match found {
                        Some(v) => v,
                        None => return Ok(None),
                    }
                }
            }
        }
        Some(QueryElement::Index(index)) => match payload.as_array().and_then(|v| v.get(*index)).cloned() {
            Some(Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, value)) => {
                let mut found = None;

                for salted in array.iter().flatten() {
                    if let Salted::Element(sc) = salted {
                        let mut cbor = vec![];
                        ciborium::into_writer(&sc, &mut cbor)?;
                        let hashed: Value = Hasher::digest(cbor.clone()).to_vec().into();
                        if *value == hashed {
                            found = Some(sc.value);
                        }
                    }
                }

                match found {
                    Some(v) => v,
                    None => return Ok(None),
                }
            }
            Some(v) => v,
            None => return Ok(None),
        },
        None => return Ok(None),
    };

    if query.len() == 1 {
        Ok(Some(value))
    } else {
        query_inner::<Hasher>(array, &value, &query[1..])
    }
}

pub trait TokenQuery {
    fn query<Hasher: digest::Digest>(&mut self, query: Query) -> EsdicawtSpecResult<Option<Value>>;
}

impl<PayloadClaims: Select, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TokenQuery for SdCwtIssued<PayloadClaims, ProtectedClaims, UnprotectedClaims> {
    fn query<Hasher: digest::Digest>(&mut self, token_query: Query) -> EsdicawtSpecResult<Option<Value>> {
        let payload: Value = Value::from_cbor_bytes(self.payload.to_bytes()?)?;
        query_inner::<Hasher>(self.disclosures(), &payload, &token_query.elements)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;
    use esdicawt_spec::{EsdicawtSpecError, Select, issuance::SdCwtIssuedTagged};
    use rand_core::SeedableRng;

    use crate::{Issuer, IssuerParams, test_utils::P256IssuerClaims};

    #[test]
    fn can_query_top_level_claim() {
        let payload = cbor!({
            "a" => "b",
            "c" => "d",
        })
        .unwrap();
        let mut sd_cwt = generate(payload);
        assert_eq!(sd_cwt.0.query::<sha2::Sha256>(vec!["a".into()].into()).unwrap(), Some("b".into()));

        let salted = &mut sd_cwt.0.sd_unprotected.sd_claims;
        salted.0.retain(|cl| cl.as_array().map(|a| a[2] != "a".into()).unwrap_or_default());

        let _ = salted;

        assert_eq!(sd_cwt.0.query::<sha2::Sha256>(vec!["a".into()].into()).unwrap(), None);
    }

    #[test]
    fn can_query_lower_level_claim() {
        let payload = cbor!({
            "a" => {
                "b" => "c",
                "d" => "e"
            },
            "b" => 1234
        })
        .unwrap();

        let mut sd_cwt = generate(payload);
        assert_eq!(sd_cwt.0.query::<sha2::Sha256>(vec!["a".into(), "b".into()].into()).unwrap(), Some("c".into()));
    }

    #[test]
    fn can_query_top_level_array_index() {
        let payload = cbor!({
            "a" => ["b", "c", "d", "e"],
            "b" => 1234
        })
        .unwrap();

        let mut sd_cwt = generate(payload);
        assert_eq!(sd_cwt.0.query::<sha2::Sha256>(vec!["a".into(), 2usize.into()].into()).unwrap(), Some("d".into()));
    }

    #[test]
    fn can_query_inside_array_index() {
        let payload = cbor!({
            "a" => [
                {
                    "b" => "c"
                },
                {
                    "b" => "d",
                    "e" => "f"
                }
            ],
            "b" => 1234
        })
        .unwrap();

        let mut sd_cwt = generate(payload);
        assert_eq!(
            sd_cwt.0.query::<sha2::Sha256>(vec!["a".into(), 1usize.into(), "b".into()].into()).unwrap(),
            Some("d".into())
        );
    }

    fn generate<T: Select<Error = EsdicawtSpecError>>(payload: T) -> SdCwtIssuedTagged<T> {
        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();

        let issuer_signing_key = p256::ecdsa::SigningKey::random(&mut csprng);
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);

        let issuer = P256IssuerClaims::new(issuer_signing_key);

        let issue_params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: Some(payload),
            subject: "mimi://example.com/u/alice.smith",
            issuer: "mimi://example.com/i/proton.me",
            expiry: core::time::Duration::from_secs(90),
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.proton.me/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
        };
        issuer.issue_cwt(&mut csprng, issue_params).unwrap()
    }
}
