#![allow(dead_code)]

mod blanket;
mod model;

pub use model::{Query, QueryElement};
use std::ops::Deref;

use crate::spec::{CwtAny, EsdicawtSpecResult, REDACTED_CLAIM_ELEMENT_TAG, blinded_claims::Salted, redacted_claims::RedactedClaimKeys};
use crate::verifier::walk::walk_payload;
use ciborium::Value;
use digest::DynDigest;
use esdicawt_spec::{EsdicawtSpecError, blinded_claims::SaltedArrayToVerify};

pub trait TokenQuery {
    fn query(&mut self, query: Query) -> EsdicawtSpecResult<Option<Value>>;
}

/// Allows reading claims in a SD-CWT even when they are redacted
pub fn query<Hasher>(salted_array: &mut SaltedArrayToVerify, payload: &Value, mut q: Query) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static,
{
    q.0.reverse();
    query_inner::<Hasher>(salted_array, &mut payload.clone(), q.0)
}

/// Allows reading claims in a SD-CWT even when they are redacted
pub fn query_encoded<Hasher>(salted_array: &mut SaltedArrayToVerify, payload: &Value, query_cbor: &[u8]) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static,
{
    query::<Hasher>(salted_array, payload, Query::from_cbor_bytes(query_cbor)?)
}

#[tailcall::tailcall]
fn query_inner<Hasher>(salted_array: &mut SaltedArrayToVerify, payload: &mut Value, mut query: Vec<QueryElement>) -> EsdicawtSpecResult<Option<Value>>
where
    Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static,
{
    let mut value = match query.pop() {
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

                    let (mut found, _) = salted_array.swap_remove(pos);
                    let Salted::Claim(sc) = found.to_mut() else { unreachable!() };
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
        _ => return Ok(None),
    };

    match &query[..] {
        [] => {
            walk_payload::<EsdicawtSpecError>(Hasher::new().box_clone(), &mut value, salted_array).unwrap();
            Ok(Some(value))
        }
        _ => query_inner::<Hasher>(salted_array, &mut value, query),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Holder, HolderParams, Issuer, IssuerParams, Presentation, StatusParams, Verifier,
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use ciborium::cbor;
    use cose_key_set::CoseKeySet;
    use esdicawt_spec::{CustomClaims, NoClaims, SdCwtClaim, Select, SelectExt, issuance::SdCwtIssuedTagged, key_binding::KbtCwtTagged, sd, verified::KbtCwtVerified};

    #[test]
    fn can_query_top_level_claim() {
        let (query, expected) = (vec!["a".into()], Some("b".into()));
        test(cbor!({"a" => "b", "c" => "d"}), &query, &expected, true, false);
        test(cbor!({sd!("a") => "b", "c" => "d"}), &query, &expected, true, true);
        test(cbor!({"a" => "b", sd!("c") => "d"}), &query, &expected, true, false);
        test(cbor!({sd!("a") => "b", sd!("c") => "d"}), &query, &expected, true, true);

        let (query, expected) = (vec!["c".into()], Some("d".into()));
        test(cbor!({"a" => "b", "c" => "d"}), &query, &expected, true, false);
        test(cbor!({sd!("a") => "b", "c" => "d"}), &query, &expected, true, false);
        test(cbor!({"a" => "b", sd!("c") => "d"}), &query, &expected, true, true);
        test(cbor!({sd!("a") => "b", sd!("c") => "d"}), &query, &expected, true, true);
    }

    #[test]
    fn can_query_lower_level_claim() {
        let query = vec!["a".into(), "b".into()];
        let expected = Some("c".into());

        test(cbor!({"a" => {"b" => "c", "d" => "e"}, "b" => 1234}), &query, &expected, true, false);
        test(cbor!({"a" => {sd!("b") => "c", "d" => "e"}, "b" => 1234}), &query, &expected, true, true);
    }

    #[test]
    fn can_query_top_level_array_index() {
        let query = vec!["a".into(), 2usize.into()];
        let expected = Some("d".into());

        test(cbor!({"a" => ["b", "c", "d", "e"], "b" => 1234}), &query, &expected, true, false);
        test(cbor!({"a" => ["b", "c", sd!("d"), "e"], "b" => 1234}), &query, &expected, true, true);
    }

    #[test]
    fn should_continue_unredacted_nested() {
        let query = vec!["a".into()];
        let expected = Some(cbor!(["b", "c", "d", "e"]).unwrap());

        test(cbor!({"a" => ["b", "c", "d", "e"], "b" => 1234}), &query, &expected, false, false);
        test(cbor!({"a" => ["b", "c", sd!("d"), "e"], "b" => 1234}), &query, &expected, false, true);
    }

    #[test]
    fn can_query_inside_array_index() {
        let query = vec!["a".into(), 1usize.into(), "b".into()];
        let expected = Some("d".into());

        test(cbor!({"a" => [{"b" => "c"}, {"b" => "d", "e" => "f"}], "b" => 1234}), &query, &expected, false, false);
        test(cbor!({"a" => [{"b" => "c"}, {sd!("b") => "d", "e" => "f"}], "b" => 1234}), &query, &expected, false, true);
    }

    /// * simple_matching: query is for a simple type (int, tstr etc...) and not an array or map
    /// * contains_redacted: does the payload contains a redacted claim AS PART OF THE QUERY RESULT
    fn test(payload: Result<Value, ciborium::value::Error>, query: &[QueryElement], expected: &Option<Value>, simple_matching: bool, contains_redacted: bool) {
        let payload = payload.unwrap().select_none().unwrap();
        let (mut sd_cwt, holder_signing_key, issuer_verifying_key) = new_sd_cwt(payload);
        let mut sd_kbt = present_sd_kbt::<Value>(&sd_cwt.to_cbor_bytes().unwrap()[..], holder_signing_key, issuer_verifying_key);
        let mut sd_kbt_verified = verify::<Value>(&sd_kbt.to_cbor_bytes().unwrap(), issuer_verifying_key);

        assert_eq!(sd_cwt.query(query.to_vec().into()).unwrap(), expected.clone());
        assert_eq!(sd_kbt.query(query.to_vec().into()).unwrap(), expected.clone());
        if !contains_redacted {
            assert_eq!(sd_kbt_verified.query(query.to_vec().into()).unwrap(), expected.clone());
        } else if simple_matching {
            sd_cwt.0.disclosures_mut().unwrap().0.clear();
            assert_eq!(sd_cwt.query(query.to_vec().into()).unwrap(), None);

            sd_kbt.0.clear_disclosures().unwrap();
            dbg!(&sd_kbt.0.disclosures());
            assert_eq!(sd_kbt.query(query.to_vec().into()).unwrap(), None);
        }
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

    fn new_sd_cwt<T: Select>(payload: T) -> (SdCwtIssuedTagged<T, sha2::Sha256>, ed25519_dalek::SigningKey, ed25519_dalek::VerifyingKey) {
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

    fn present_sd_kbt<T: Select>(sd_cwt: &[u8], holder_signing_key: ed25519_dalek::SigningKey, issuer_verifying_key: ed25519_dalek::VerifyingKey) -> KbtCwtTagged<T, sha2::Sha256> {
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

    fn verify<T: Select>(sd_kbt: &[u8], issuer_verifying_key: ed25519_dalek::VerifyingKey) -> KbtCwtVerified<T> {
        pub struct Ed25519Verifier<T: Select, U: CustomClaims = NoClaims> {
            pub _marker: core::marker::PhantomData<(T, U)>,
        }

        #[allow(clippy::new_without_default)]
        impl<T: Select, U: CustomClaims> Ed25519Verifier<T, U> {
            pub fn new() -> Self {
                Self { _marker: Default::default() }
            }
        }

        impl<T: Select, U: CustomClaims> Verifier for Ed25519Verifier<T, U> {
            type Error = std::convert::Infallible;
            type HolderSignature = ed25519_dalek::Signature;
            type HolderVerifier = ed25519_dalek::VerifyingKey;
            type IssuerProtectedClaims = NoClaims;
            type IssuerUnprotectedClaims = NoClaims;
            type IssuerPayloadClaims = T;
            type KbtPayloadClaims = U;
            type KbtProtectedClaims = NoClaims;
            type KbtUnprotectedClaims = NoClaims;
        }
        let verifier = Ed25519Verifier::new();
        verifier
            .verify_sd_kbt(sd_kbt, Default::default(), None, &CoseKeySet::new(&issuer_verifying_key).unwrap())
            .unwrap()
    }
}
