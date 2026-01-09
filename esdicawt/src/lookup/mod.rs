#![allow(dead_code)]

mod blanket;
mod model;

pub use model::{Query, QueryElement};
use std::ops::Deref;

use crate::spec::{CwtAny, EsdicawtSpecResult, REDACTED_CLAIM_ELEMENT_TAG, blinded_claims::Salted, redacted_claims::RedactedClaimKeys};
use ciborium::Value;
use esdicawt_spec::{EsdicawtSpecError, blinded_claims::SaltedArrayToVerify};

pub fn query<Hasher>(salted_array: &mut SaltedArrayToVerify, payload: &Value, query: &[u8]) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest,
{
    let mut query = Query::from_cbor_bytes(query)?.0;
    query.reverse();
    query_inner::<Hasher>(salted_array, payload, query)
}

fn query_inner<Hasher>(salted_array: &mut SaltedArrayToVerify, payload: &Value, mut query: Vec<QueryElement>) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest,
{
    let value = match query.pop() {
        Some(QueryElement::ClaimName(claim_name)) => {
            let map = payload.as_map().ok_or(EsdicawtSpecError::LookupError("Query label not in an map"))?;
            let name_label = claim_name.to_cbor_value()?;

            // check the presence in the payload
            match map.iter().find_map(|(k, v)| (k == &name_label).then(|| v.clone())) {
                Some(v) => v,
                None => {
                    // if not in the payload, we will look in the salted array
                    const RCKS_KEY: Value = Value::Simple(RedactedClaimKeys::CWT_LABEL);
                    let Some(rcks) = map.iter().find_map(|(k, v)| (k == &RCKS_KEY).then_some(v)).and_then(Value::as_array) else {
                        return Ok(None);
                    };

                    let Some(pos) = salted_array.iter_mut().position(|(salted, digest)| {
                        if let Salted::Claim(sc) = salted.as_ref()
                            && sc.name == claim_name
                        {
                            // if we found an element with a matching claim name, check that it is present in the payload's
                            // redacted claim keys list
                            let digest: Value = match digest {
                                Some(digest) => digest.as_slice().into(),
                                entry => {
                                    let Ok(cbor_bytes) = sc.to_cbor_bytes() else {
                                        // this salted cannot be hashed, ignore it
                                        return false;
                                    };
                                    let digest = Hasher::digest(cbor_bytes);
                                    entry.replace(digest.to_vec());
                                    digest.deref().into()
                                }
                            };
                            return rcks.contains(&digest);
                        }
                        false
                    }) else {
                        return Ok(None);
                    };

                    let found = salted_array.swap_remove(pos);
                    let Salted::Claim(sc) = found.0.as_ref() else { unreachable!() };
                    sc.value.clone()
                }
            }
        }
        Some(QueryElement::Index(index)) => {
            let array = payload.as_array().ok_or(EsdicawtSpecError::LookupError("Query index not in an array"))?;
            match array.get(index) {
                Some(Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, value)) => {
                    let Some(pos) = salted_array.iter_mut().position(|(salted, digest)| {
                        if let Salted::Element(sc) = salted.as_ref() {
                            let digest: Value = match digest {
                                Some(digest) => digest.as_slice().into(),
                                entry => {
                                    let Ok(cbor_bytes) = sc.to_cbor_bytes() else {
                                        // this salted cannot be hashed, ignore it
                                        return false;
                                    };
                                    let digest = Hasher::digest(cbor_bytes);
                                    entry.replace(digest.to_vec());
                                    digest.deref().into()
                                }
                            };
                            return **value == digest;
                        }
                        false
                    }) else {
                        return Ok(None);
                    };

                    let found = salted_array.swap_remove(pos);
                    let Salted::Element(sc) = found.0.as_ref() else { unreachable!() };
                    sc.value.clone()
                }
                Some(v) => v.clone(),
                None => return Ok(None),
            }
        }
        Some(QueryElement::Wildcard) => {
            let mut payload = payload.clone();
            let array = payload.as_array_mut().ok_or(EsdicawtSpecError::LookupError("Query wildcard not in an array"))?;

            for element in array.iter_mut() {
                if let Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, value) = element {
                    let Some(pos) = salted_array.iter_mut().position(|(salted, digest)| {
                        if let Salted::Element(sc) = salted.as_ref() {
                            let digest: Value = match digest {
                                Some(digest) => digest.as_slice().into(),
                                entry => {
                                    let Ok(cbor_bytes) = sc.to_cbor_bytes() else {
                                        // this salted cannot be hashed, ignore it
                                        return false;
                                    };
                                    let digest = Hasher::digest(cbor_bytes);
                                    entry.replace(digest.to_vec());
                                    digest.deref().into()
                                }
                            };

                            return **value == digest;
                        }
                        false
                    }) else {
                        return Ok(None);
                    };

                    let found = salted_array.swap_remove(pos);
                    let Salted::Element(sc) = found.0.as_ref() else { unreachable!() };
                    *element = sc.value.clone();
                }
            }
            return Ok(Some(Value::Array(array.clone())));
        }
        _ => return Ok(None),
    };

    match &query[..] {
        [] => Ok(Some(value)),
        _ => query_inner::<Hasher>(salted_array, &value, query),
    }
}

pub trait TokenQuery {
    fn query(&mut self, query: Query) -> EsdicawtSpecResult<Option<Value>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Holder, HolderParams, Issuer, IssuerParams, Presentation, StatusParams,
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use ciborium::cbor;
    use cose_key_set::CoseKeySet;
    use esdicawt_spec::{SdCwtClaim, Select, SelectExt, issuance::SdCwtIssuedTagged, key_binding::KbtCwtTagged, sd};

    #[test]
    fn can_query_top_level_claim() {
        let test = |payload: Result<Value, ciborium::value::Error>, a_redacted: bool| {
            let payload = payload.unwrap().select_none().unwrap();
            let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = generate(payload);
            let mut sd_kbt = present::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);
            assert_eq!(sd_cwt.query(vec!["a".into()].into()).unwrap(), Some("b".into()));
            assert_eq!(sd_cwt.query(vec!["c".into()].into()).unwrap(), Some("d".into()));
            assert_eq!(sd_kbt.query(vec!["a".into()].into()).unwrap(), Some("b".into()));
            assert_eq!(sd_kbt.query(vec!["c".into()].into()).unwrap(), Some("d".into()));

            if a_redacted {
                let salted = sd_cwt.0.disclosures_mut().unwrap();
                #[allow(clippy::indexing_slicing)]
                salted
                    .0
                    .retain_mut(|cl| cl.to_value().unwrap().value().unwrap().as_array().map(|a| a[2] != "a".into()).unwrap_or_default());

                let _ = salted;

                assert_eq!(sd_cwt.query(vec!["a".into()].into()).unwrap(), None);
            }
        };

        test(cbor!({"a" => "b", "c" => "d"}), false); // unredacted
        test(cbor!({sd!("a") => "b", "c" => "d"}), true); // a redacted
        test(cbor!({"a" => "b", sd!("c") => "d"}), false); // c redacted
        test(cbor!({sd!("a") => "b", sd!("c") => "d"}), true); // all redacted
    }

    #[test]
    fn can_query_lower_level_claim() {
        let test = |payload: Result<Value, ciborium::value::Error>| {
            let payload = payload.unwrap().select_none().unwrap();
            let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = generate(payload);
            let mut sd_kbt = present::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);
            assert_eq!(sd_cwt.query(vec!["a".into(), "b".into()].into()).unwrap(), Some("c".into()));
            assert_eq!(sd_kbt.query(vec!["a".into(), "b".into()].into()).unwrap(), Some("c".into()));
        };

        test(cbor!({"a" => {"b" => "c", "d" => "e"}, "b" => 1234})); // unredacted
        test(cbor!({"a" => {sd!("b") => "c", "d" => "e"}, "b" => 1234})); // assert redacted
    }

    #[test]
    fn can_query_top_level_array_index() {
        let test = |payload: Result<Value, ciborium::value::Error>| {
            let payload = payload.unwrap().select_none().unwrap();
            let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = generate(payload);
            let mut sd_kbt = present::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);
            assert_eq!(sd_cwt.query(vec!["a".into(), 2usize.into()].into()).unwrap(), Some("d".into()));
            assert_eq!(sd_kbt.query(vec!["a".into(), 2usize.into()].into()).unwrap(), Some("d".into()));
        };

        test(cbor!({"a" => ["b", "c", "d", "e"], "b" => 1234})); // unredacted
        test(cbor!({"a" => ["b", "c", sd!("d"), "e"], "b" => 1234})); // assert redacted
    }

    #[test]
    fn wildcard_query() {
        let test = |payload: Result<Value, ciborium::value::Error>| {
            let payload = payload.unwrap().select_none().unwrap();
            let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = generate(payload);
            let mut sd_kbt = present::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);

            assert_eq!(
                sd_cwt.query(vec!["a".into(), QueryElement::Wildcard].into()).unwrap(),
                Some(cbor!(["b", "c", "d", "e"]).unwrap())
            );
            assert_eq!(
                sd_kbt.query(vec!["a".into(), QueryElement::Wildcard].into()).unwrap(),
                Some(cbor!(["b", "c", "d", "e"]).unwrap())
            );
        };

        test(cbor!({"a" => ["b", "c", "d", "e"], "b" => 1234})); // unredacted
        test(cbor!({"a" => ["b", "c", sd!("d"), "e"], "b" => 1234})); // assert redacted
    }

    #[test]
    fn can_query_inside_array_index() {
        let test = |payload: Result<Value, ciborium::value::Error>| {
            let payload = payload.unwrap().select_none().unwrap();
            let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = generate(payload);
            let mut sd_kbt = present::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);
            assert_eq!(sd_cwt.query(vec!["a".into(), 1usize.into(), "b".into()].into()).unwrap(), Some("d".into()));
            assert_eq!(sd_kbt.query(vec!["a".into(), 1usize.into(), "b".into()].into()).unwrap(), Some("d".into()));
        };

        test(cbor!({"a" => [{"b" => "c"}, {"b" => "d", "e" => "f"}], "b" => 1234})); // unredacted
        test(cbor!({"a" => [{"b" => "c"}, {sd!("b") => "d", "e" => "f"}], "b" => 1234})); // assert redacted
    }

    #[test]
    fn query_element_deser_should_roundtrip() {
        let elements = [
            QueryElement::Index(42),
            QueryElement::ClaimName(SdCwtClaim::Int(42.into())),
            QueryElement::ClaimName(SdCwtClaim::Tstr("hello".into())),
        ];
        for e in elements {
            let r = QueryElement::from_cbor_bytes(&e.to_cbor_bytes().unwrap()).unwrap();
            assert_eq!(e, r);
        }
    }

    fn generate<T: Select>(payload: T) -> (SdCwtIssuedTagged<T, sha2::Sha256>, ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let issuer = Ed25519Issuer::new(issuer_signing_key.clone());

        let issue_params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: Some(payload),
            issuer: "https://example.com/i/proton.me",
            subject: Some("https://example.com/u/alice.smith"),
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            expiry: None,
            with_not_before: true,
            with_issued_at: true,
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.proton.me/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            artificial_time: None,
            status: StatusParams {
                status_list_bit_index: 0,
                uri: "https://example.com/statuslists/1".parse().unwrap(),
            },
        };
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issue_params).unwrap();
        (sd_cwt, holder_signing_key, *issuer_signing_key.as_ref())
    }

    fn present<T: Select>(sd_cwt: &[u8], holder_signing_key: ed25519_dalek::SigningKey, issuer_verifying_key: ed25519_dalek::VerifyingKey) -> KbtCwtTagged<T, sha2::Sha256> {
        let holder = Ed25519Holder::new(holder_signing_key);

        let holder_params = HolderParams {
            presentation: Presentation::Full,
            audience: "",
            cnonce: None,
            expiry: None,
            with_not_before: false,
            artificial_time: None,
            time_verification: Default::default(),
            leeway: Default::default(),
            extra_kbt_protected: None,
            extra_kbt_unprotected: None,
            extra_kbt_payload: None,
        };
        let sd_cwt = holder.verify_sd_cwt(sd_cwt, Default::default(), &CoseKeySet::new(&issuer_verifying_key).unwrap()).unwrap();
        holder.new_presentation(sd_cwt, holder_params).unwrap()
    }
}
