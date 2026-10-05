use crate::{
    SdCwtIssuerError,
    spec::{
        CwtAny, Salt, SdCwtClaim, TO_BE_DECOY_TAG, TO_BE_REDACTED_TAG,
        blinded_claims::{Decoy, SaltedArray, SaltedClaimRef, SaltedElementRef},
        redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
    },
};
use ciborium::Value;
use std::{collections::HashSet, ops::DerefMut};

/// Redacts the claims in this Value by recursively traversing, depth-first the ClaimSet
pub fn redact<E, Hasher>(csprng: &mut dyn rand_core::CryptoRngCore, payload: &mut Value) -> Result<SaltedArray, SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    let mut sd_claims = SaltedArray::default();
    let mut decoys = HashSet::new();
    redact_value::<E, Hasher>(payload, csprng, &mut sd_claims, &mut decoys, None)?;
    Ok(sd_claims)
}

// wrapping "_redact" is required for fallible recursion
fn redact_value<E, Hasher>(
    value: &mut Value,
    csprng: &mut dyn rand_core::CryptoRngCore,
    sd_claims: &mut SaltedArray,
    decoys: &mut HashSet<u64>,
    parent_ctx: Option<(&SdCwtClaim, &mut RedactedClaimKeys)>,
) -> Result<(), SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    _redact::<E, Hasher>(value, csprng, sd_claims, decoys, parent_ctx)
}

#[tailcall::tailcall]
fn _redact<E, H>(
    mut value: &mut Value,
    csprng: &mut dyn rand_core::CryptoRngCore,
    sd_claims: &mut SaltedArray,
    decoys: &mut HashSet<u64>,
    parent_ctx: Option<(&SdCwtClaim, &mut RedactedClaimKeys)>,
) -> Result<(), SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    H: digest::Digest,
{
    match value.deref_mut() {
        Value::Map(mapping) => {
            let mut rcks = RedactedClaimKeys::with_capacity(mapping.len());
            let mut redacted = vec![];
            for (i, (label, claim_value)) in mapping.iter_mut().enumerate() {
                match label {
                    Value::Tag(TO_BE_DECOY_TAG, decoy_index) => {
                        // a decoy in a mapping: its digest goes in the 'redacted_claim_keys' and the entry is removed
                        if !claim_value.is_null() {
                            return Err(SdCwtIssuerError::CwtError("A decoy's mapping value must be null"));
                        }
                        let decoy = new_decoy(csprng, decoy_index, decoys)?;
                        sd_claims.push_ref_bytes::<()>(decoy)?;
                        rcks.push::<H>(&decoy)?;
                        redacted.push(i);
                        continue;
                    }
                    Value::Tag(TO_BE_REDACTED_TAG, _) => {
                        redacted.push(i);
                    }
                    _ => {}
                }

                let label = Value::deserialized::<SdCwtClaim>(label)?;
                redact_value::<E, H>(claim_value, csprng, sd_claims, decoys, Some((&label, &mut rcks)))?;
            }

            // removal indexes need to be sorted in decreasing order
            redacted.sort();
            redacted.reverse();

            for r in redacted {
                mapping.remove(r);
            }
            if !rcks.is_empty() {
                mapping.push(rcks.into_map_entry()?);
            }

            // if we are ourselves in a mapping then redact the mapping itself
            let parent_ctx = parent_ctx.map(|(l, rcks)| (l.untag(), rcks));
            if let Some((Some(parent_label), rcks)) = parent_ctx {
                let salt = new_salt(csprng)?;
                let salted_claim = SaltedClaimRef { salt, name: &parent_label, value };
                rcks.push::<H>(&salted_claim)?;
                sd_claims.push_ref_bytes(salted_claim)?;
            }
        }
        Value::Array(array) => {
            for element in array.iter_mut() {
                redact_value::<E, H>(element, csprng, sd_claims, decoys, None)?;
            }

            // if we are in a mapping then redact the array itself
            let parent_ctx = parent_ctx.map(|(l, rcks)| (l.untag(), rcks));
            if let Some((Some(parent_label), rcks)) = parent_ctx {
                let salt = new_salt(csprng)?;
                let salted_claim = SaltedClaimRef { salt, name: &parent_label, value };
                rcks.push::<H>(&salted_claim)?;
                sd_claims.push_ref_bytes(salted_claim)?;
            }
        }
        Value::Tag(TO_BE_REDACTED_TAG, original_value) if (original_value.is_map() || original_value.is_array()) => {
            let in_array = parent_ctx.is_none();

            redact_value::<E, H>(original_value, csprng, sd_claims, decoys, parent_ctx)?;

            // if we are in an array then redact in place
            if in_array {
                let salt = new_salt(csprng)?;
                let salted_element = SaltedElementRef { salt, value: original_value };
                let rce = RedactedClaimElement::from_salted_entry::<H>(&salted_element)?;
                sd_claims.push_ref_bytes(salted_element)?;
                *value = rce.to_cbor_value()?;
            }
        }
        value => {
            match parent_ctx {
                Some((parent_label, rcks)) => {
                    // ... in a Mapping. So we insert it in the disclosures and push the digest to it's parent 'redacted_claim_keys'

                    if let Value::Tag(TO_BE_DECOY_TAG, _) = value {
                        return Err(SdCwtIssuerError::CwtError("To Be Decoy tag not allowed in mapping values"));
                    }

                    // unwrap tagged values
                    let value = match value {
                        Value::Tag(TO_BE_REDACTED_TAG, value) => value,
                        value => value,
                    };

                    if let Some(parent_label) = parent_label.untag() {
                        let salt = new_salt(csprng)?;
                        let salted_claim = SaltedClaimRef { salt, name: &parent_label, value };
                        rcks.push::<H>(&salted_claim)?;
                        sd_claims.push_ref_bytes(salted_claim)?;
                    }
                }
                None => {
                    if let Value::Tag(TO_BE_DECOY_TAG, decoy_index) = value {
                        // ... a decoy in an Array. So we insert it in the disclosures and replace the element with its digest in the array
                        let decoy = new_decoy(csprng, decoy_index, decoys)?;
                        let rce = RedactedClaimElement::from_salted_entry::<H>(&decoy)?;
                        sd_claims.push_ref_bytes::<()>(decoy)?;
                        *value = rce.to_cbor_value()?;
                    } else if let Value::Tag(TO_BE_REDACTED_TAG, original_value) = value {
                        // ... in an Array. So we insert it in the disclosures and replace the element with its digest in the array
                        let salt = new_salt(csprng)?;
                        let salted_element = SaltedElementRef { salt, value: original_value };
                        let rce = RedactedClaimElement::from_salted_entry::<H>(&salted_element)?;
                        sd_claims.push_ref_bytes(salted_element)?;
                        *value = rce.to_cbor_value()?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// Creates a decoy for the To Be Decoy tag containing `decoy_index`, which must be an unsigned integer unique in the CWT
/// see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-to-be-decoy
fn new_decoy<E>(csprng: &mut dyn rand_core::CryptoRngCore, decoy_index: &Value, decoys: &mut HashSet<u64>) -> Result<Decoy, SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
{
    let decoy_index = decoy_index
        .as_integer()
        .and_then(|i| u64::try_from(i).ok())
        .ok_or(SdCwtIssuerError::CwtError("To Be Decoy tag must contain an unsigned integer"))?;
    if !decoys.insert(decoy_index) {
        return Err(SdCwtIssuerError::CwtError("To Be Decoy tag must contain an integer unique in the CWT"));
    }
    Ok(Decoy { salt: new_salt(csprng)? })
}

fn new_salt<E>(csprng: &mut dyn rand_core::CryptoRngCore) -> Result<Salt, SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
{
    let mut salt = Salt::empty();
    csprng.try_fill_bytes(&mut *salt)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{
        REDACTED_CLAIM_ELEMENT_TAG,
        blinded_claims::{SaltedClaim, SaltedElement, SaltedEntry},
        decoy,
        redacted_claims::ToRedacted,
        sd,
    };
    use ciborium::cbor;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[allow(clippy::cognitive_complexity)]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_primitive_claim_in_mapping() {
        let payload = Value::Map(vec![
            (sd!("a"), Value::Integer(1.into())),
            (sd!(2), Value::Text("b".into())),
            (sd!(3), Value::Null),
            (sd!(4), Value::Bool(false)),
            (sd!(5), Value::Float(14.3)),
        ]);
        let (payload, [d1, d2, d3, d4, d5]) = _redact(payload);

        // --- altered payload ---
        let rck = get_redacted_claim_keys::<5>(&payload);
        let payload = payload.as_map().unwrap();

        // all redacted claims have been removed
        assert!(!payload.iter().any(|(k, _)| k == &cbor!("a").unwrap()));
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(2).unwrap()));
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(3).unwrap()));
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(4).unwrap()));
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(5).unwrap()));

        // --- disclosures ---
        let d1 = d1.deserialized::<SaltedClaim<u64>>().unwrap();
        std::assert_matches!(&d1.name, SdCwtClaim::Tstr(n) if n == "a");
        assert_eq!(d1.value, 1);
        assert!(rck_contains_digest(&rck, &d1));

        let d2 = d2.deserialized::<SaltedClaim<String>>().unwrap();
        std::assert_matches!(&d2.name, SdCwtClaim::Int(n) if *n == 2);
        assert_eq!(&d2.value, "b");
        assert!(rck_contains_digest(&rck, &d2));

        let d3 = d3.deserialized::<SaltedClaim<Option<u8>>>().unwrap();
        std::assert_matches!(&d3.name, SdCwtClaim::Int(n) if *n == 3);
        assert_eq!(d3.value, None);
        assert!(rck_contains_digest(&rck, &d3));

        let d4 = d4.deserialized::<SaltedClaim<bool>>().unwrap();
        std::assert_matches!(&d4.name, SdCwtClaim::Int(n) if *n == 4);
        assert!(!d4.value);
        assert!(rck_contains_digest(&rck, &d4));

        let d5 = d5.deserialized::<SaltedClaim<f64>>().unwrap();
        std::assert_matches!(&d5.name, SdCwtClaim::Int(n) if *n == 5);
        assert_eq!(d5.value, 14.3);
        assert!(rck_contains_digest(&rck, &d5));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_array() {
        let payload = Value::Map(vec![(sd!(1), Value::Array(vec![sd!("a"), sd!("b")]))]);
        let (payload, [d1, d2, d3]) = _redact(payload);

        // --- altered payload ---
        let rck = get_redacted_claim_keys::<1>(&payload);
        let payload = payload.as_map().unwrap();

        // all redacted claims have been removed
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(1).unwrap()));

        let d3 = d3.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        std::assert_matches!(&d3.name, SdCwtClaim::Int(n) if *n == 1);
        assert!(rck_contains_digest(&rck, &d3));

        // verify that the disclosure of mapping claim '1' contains a redacted array which itself
        // contains the redacted in place elements "a" and "b"
        let [a, b]: [RedactedClaimElement; 2] = d3.value.try_into().unwrap();

        assert_eq!(a.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d1).unwrap()));

        assert_eq!(b.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d2).unwrap()));

        let d1 = d1.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d1.value, "a".to_string());

        let d2 = d2.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d2.value, "b".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_array_nested() {
        let payload = Value::Map(vec![(sd!(1), Value::Array(vec![sd!(Value::Array(vec![sd!("a"), sd!("b")]))]))]);
        let (payload, [d1, d2, d3, d4]) = _redact(payload);

        // --- altered payload ---
        let rck = get_redacted_claim_keys::<1>(&payload);
        let payload = payload.as_map().unwrap();

        // all redacted claims have been removed
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(1).unwrap()));

        let d4 = d4.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        std::assert_matches!(&d4.name, SdCwtClaim::Int(n) if *n == 1);
        assert!(rck_contains_digest(&rck, &d4));

        // verify that the disclosure of mapping claim '1' contains a redacted array which itself
        // contains a redacted array which itself contains the redacted in place elements "a" & "b"
        let [nested_array]: [RedactedClaimElement; 1] = d4.value.try_into().unwrap();
        assert_eq!(nested_array.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d3).unwrap()));

        let d3 = d3.deserialized::<SaltedElement<Vec<RedactedClaimElement>>>().unwrap();
        let [a, b]: [RedactedClaimElement; 2] = d3.value.try_into().unwrap();
        assert_eq!(a.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d1).unwrap()));
        assert_eq!(b.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d2).unwrap()));

        let d1 = d1.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d1.value, "a".to_string());

        let d2 = d2.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d2.value, "b".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_nested_mapping() {
        let payload = Value::Map(vec![(sd!(0), Value::Map(vec![(sd!(1), Value::Text("a".into()))]))]);
        let (payload, [d1, d0]) = _redact(payload);

        // --- depth 0 ---
        let rck0 = get_redacted_claim_keys::<1>(&payload);
        let payload0 = payload.as_map().unwrap();
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(0).unwrap()));

        // --- disclosures ---
        let d0 = d0.deserialized::<SaltedClaim<Value>>().unwrap();
        std::assert_matches!(&d0.name, SdCwtClaim::Int(i) if *i == 0);
        assert!(rck_contains_digest(&rck0, &d0));

        // --- depth 1 ---
        let payload1 = d0.value;
        let rck1 = get_redacted_claim_keys::<1>(&payload1);
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(1).unwrap()));
        assert!(rck_contains_digest(&rck1, &SaltedEntry::<Value>::from_cbor_value(&d1).unwrap()));

        // --- disclosures ---
        let d1 = d1.deserialized::<SaltedClaim<String>>().unwrap();
        std::assert_matches!(&d1.name, SdCwtClaim::Int(i) if *i == 1);
        assert_eq!(d1.value, "a".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_mapping_nested_in_array() {
        let payload = Value::Map(vec![(sd!(0), Value::Array(vec![sd!(Value::Map(vec![(sd!(1), Value::Integer(2.into()))]))]))]);
        let (payload, [d2, d1, d0]) = _redact(payload);

        // --- depth 0 ---
        let rck0 = get_redacted_claim_keys::<1>(&payload);
        assert!(rck_contains_digest(&rck0, &SaltedEntry::<Value>::from_cbor_value(&d0).unwrap()));

        let payload0 = payload.as_map().unwrap();
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(0).unwrap()));

        // --- depth 2 ---
        let d2 = d2.deserialized::<SaltedClaim<u64>>().unwrap();
        std::assert_matches!(&d2.name, SdCwtClaim::Int(n) if *n == 1);
        assert_eq!(d2.value, 2);

        // --- depth 1 ---
        let d1 = d1.deserialized::<SaltedElement<Value>>().unwrap();
        let rck1 = get_redacted_claim_keys::<1>(&d1.value);
        let payload1 = d1.value.as_map().unwrap();
        assert!(!payload1.iter().any(|(k, _)| k == &cbor!(1).unwrap()));
        assert!(rck_contains_digest(&rck1, &d2));

        // --- depth 0, again ---
        let d0 = d0.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        std::assert_matches!(&d0.name, SdCwtClaim::Int(n) if *n == 0);

        let [mapping12]: [RedactedClaimElement; 1] = d0.value.try_into().unwrap();
        assert_eq!(mapping12.to_cbor_value().unwrap(), element_digest(&d1));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_insert_decoy_in_array() {
        let payload = Value::Map(vec![(Value::Integer(1.into()), Value::Array(vec![Value::Text("a".into()), decoy!(1)]))]);
        let (payload, [d1]) = _redact(payload);

        // the element is replaced in place by the decoy digest
        let payload = payload.as_map().unwrap();
        let [(_, array)] = payload.as_slice() else { panic!("Expected a single claim") };
        let [a, decoy] = array.as_array().unwrap().as_slice() else {
            panic!("Expected 2 elements")
        };
        assert_eq!(a, &Value::Text("a".into()));

        let d1 = SaltedEntry::<Value>::from_cbor_value(&d1).unwrap();
        std::assert_matches!(d1, SaltedEntry::Decoy(_));
        assert_eq!(decoy, &element_digest(&d1));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_insert_decoys_in_mapping() {
        let payload = Value::Map(vec![
            (Value::Integer(1.into()), Value::Text("a".into())),
            (decoy!(1), Value::Null),
            (decoy!(2), Value::Null),
        ]);
        let (payload, [d1, d2]) = _redact(payload);

        // the decoy entries are replaced by their digest in the 'redacted_claim_keys'
        let rck = get_redacted_claim_keys::<2>(&payload);
        let payload = payload.as_map().unwrap();
        assert_eq!(payload.len(), 2);
        assert!(!payload.iter().any(|(k, _)| matches!(k, Value::Tag(TO_BE_DECOY_TAG, _))));

        for d in [d1, d2] {
            let d = SaltedEntry::<Value>::from_cbor_value(&d).unwrap();
            std::assert_matches!(d, SaltedEntry::Decoy(_));
            assert!(rck_contains_digest(&rck, &d));
        }
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_insert_decoy_in_redacted_array() {
        let payload = Value::Map(vec![(sd!(1), Value::Array(vec![sd!("a"), decoy!(1)]))]);
        let (payload, [d1, d2, d3]) = _redact(payload);

        let rck = get_redacted_claim_keys::<1>(&payload);
        let d3 = d3.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        assert!(rck_contains_digest(&rck, &d3));

        let [a, decoy]: [RedactedClaimElement; 2] = d3.value.try_into().unwrap();
        assert_eq!(a.to_cbor_value().unwrap(), element_digest(&SaltedEntry::<Value>::from_cbor_value(&d1).unwrap()));
        let d2 = SaltedEntry::<Value>::from_cbor_value(&d2).unwrap();
        std::assert_matches!(d2, SaltedEntry::Decoy(_));
        assert_eq!(decoy.to_cbor_value().unwrap(), element_digest(&d2));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_reject_invalid_decoys() {
        let int = |i: i64| Value::Integer(i.into());

        // the decoy integer must be unique in the CWT, not just at a given level
        let duplicate = Value::Map(vec![(decoy!(1), Value::Null), (int(2), Value::Array(vec![decoy!(1)]))]);
        std::assert_matches!(try_redact(duplicate), Err(SdCwtIssuerError::CwtError(m)) if m.contains("unique"));

        // a decoy in a mapping must have a null value
        let not_null = Value::Map(vec![(decoy!(1), Value::Bool(true))]);
        std::assert_matches!(try_redact(not_null), Err(SdCwtIssuerError::CwtError(m)) if m.contains("must be null"));

        // a decoy can only contain an unsigned integer
        let text = Value::Map(vec![(int(1), Value::Array(vec![Value::Tag(TO_BE_DECOY_TAG, Value::Text("a".into()).into())]))]);
        std::assert_matches!(try_redact(text), Err(SdCwtIssuerError::CwtError(m)) if m.contains("unsigned integer"));
        let negative = Value::Map(vec![(Value::Tag(TO_BE_DECOY_TAG, int(-1).into()), Value::Null)]);
        std::assert_matches!(try_redact(negative), Err(SdCwtIssuerError::CwtError(m)) if m.contains("unsigned integer"));

        // a decoy cannot be a mapping value
        let map_value = Value::Map(vec![(int(1), decoy!(1))]);
        std::assert_matches!(try_redact(map_value), Err(SdCwtIssuerError::CwtError(m)) if m.contains("not allowed in mapping values"));
    }

    fn try_redact(mut payload: Value) -> Result<SaltedArray, SdCwtIssuerError<Error>> {
        redact::<Error, sha2::Sha256>(&mut rand::thread_rng(), &mut payload)
    }

    // TODO: if got time change return to '(Value, [Salted<Value>; N])'
    fn _redact<const N: usize>(mut payload: Value) -> (Value, [Value; N]) {
        let sd_claims = redact::<Error, sha2::Sha256>(&mut rand::thread_rng(), &mut payload).unwrap();

        for d in sd_claims.iter() {
            let d = d.unwrap();
            assert_eq!(d.salt().len(), Salt::SIZE);
        }

        let size = sd_claims.len();
        let disclosures = sd_claims.iter().map(|s| s.unwrap().clone()).map(|s| s.to_cbor_value().unwrap()).collect::<Vec<_>>();
        let disclosures = disclosures.try_into().unwrap_or_else(|_| panic!("Expected {N} disclosures but got {size}"));

        (payload, disclosures)
    }

    fn rck_contains_digest(rck: &[Value], salted: &impl ToRedacted) -> bool {
        let redacted = digest(salted);
        rck.iter().map(|r| r.as_bytes().unwrap()).any(|r| r == &redacted)
    }

    fn element_digest(salted: &impl ToRedacted) -> Value {
        Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, Value::Bytes(digest(salted)).into())
    }

    fn digest(salted: &impl ToRedacted) -> Vec<u8> {
        #[cfg(not(feature = "backward"))]
        return salted.to_redacted::<sha2::Sha256>().unwrap().to_vec();
        #[cfg(feature = "backward")]
        return salted.old_to_redacted::<sha2::Sha256>().unwrap().to_vec();
    }

    fn get_redacted_claim_keys<const N: usize>(payload: &Value) -> [Value; N] {
        let payload = payload.as_map().unwrap();
        let (_, rck) = payload.iter().find(|(k, _)| k.as_simple() == Some(RedactedClaimKeys::CWT_LABEL)).unwrap();
        rck.as_array().unwrap().clone().try_into().unwrap()
    }

    #[derive(Debug, thiserror::Error)]
    struct Error;
    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{self:?}")
        }
    }
}
