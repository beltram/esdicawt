use crate::SdCwtIssuerError;
use ciborium::Value;
use esdicawt_spec::{
    ClaimName, CwtAny, Salt, TO_BE_REDACTED_TAG,
    blinded_claims::{SaltedArray, SaltedClaimRef, SaltedElementRef},
    redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
};
use std::ops::DerefMut;

/// Redacts the claims in this Value by recursively traversing, depth-first the ClaimSet
pub fn redact<E, Hasher>(csprng: &mut dyn rand_core::CryptoRngCore, disclosable_claims: &mut Value) -> Result<SaltedArray, SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    let mut sd_claims = SaltedArray::default();
    redact_value::<E, Hasher>(disclosable_claims, csprng, &mut sd_claims, None)?;
    Ok(sd_claims)
}

// wrapping "_redact" is required for fallible recursion
fn redact_value<E, Hasher>(
    value: &mut Value,
    csprng: &mut dyn rand_core::CryptoRngCore,
    sd_claims: &mut SaltedArray,
    parent_ctx: Option<(&ClaimName, &mut RedactedClaimKeys)>,
) -> Result<(), SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    _redact::<E, Hasher>(value, csprng, sd_claims, parent_ctx)
}

#[tailcall::tailcall]
fn _redact<E, Hasher>(
    mut value: &mut Value,
    csprng: &mut dyn rand_core::CryptoRngCore,
    sd_claims: &mut SaltedArray,
    parent_ctx: Option<(&ClaimName, &mut RedactedClaimKeys)>,
) -> Result<(), SdCwtIssuerError<E>>
where
    E: core::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    let digest = |v: &Value| Result::<_, SdCwtIssuerError<E>>::Ok(Hasher::digest(&v.to_cbor_bytes()?));
    match value.deref_mut() {
        Value::Map(mapping) => {
            let mut rcks = RedactedClaimKeys::with_capacity(mapping.len());
            let mut redacted = vec![];
            for (i, (label, claim_value)) in mapping.iter_mut().enumerate() {
                if let Value::Tag(TO_BE_REDACTED_TAG, _) = label {
                    redacted.push(i);
                };
                let label = Value::deserialized::<ClaimName>(label)?;
                redact_value::<E, Hasher>(claim_value, csprng, sd_claims, Some((&label, &mut rcks)))?;
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
                let salt = &new_salt(csprng)?;
                let salted_claim = sd_claims.push_ref(SaltedClaimRef {
                    salt,
                    claim: &parent_label,
                    value,
                })?;
                rcks.push(&digest(salted_claim)?[..]);
            }
        }
        Value::Array(array) => {
            for element in array.iter_mut() {
                redact_value::<E, Hasher>(element, csprng, sd_claims, None)?;
            }

            // if we are in a mapping then redact the array itself
            let parent_ctx = parent_ctx.map(|(l, rcks)| (l.untag(), rcks));
            if let Some((Some(parent_label), rcks)) = parent_ctx {
                let salt = &new_salt(csprng)?;
                let disclosure = SaltedClaimRef {
                    salt,
                    claim: &parent_label,
                    value,
                };
                let salted_claim = sd_claims.push_ref(disclosure)?;
                rcks.push(&digest(salted_claim)?[..]);
            }
        }
        Value::Tag(tag, original_value) if *tag == TO_BE_REDACTED_TAG && (original_value.is_map() || original_value.is_array()) => {
            let in_array = parent_ctx.is_none();

            redact_value::<E, Hasher>(original_value, csprng, sd_claims, parent_ctx)?;

            // if we are in an array then redact in place
            if in_array {
                let salt = &new_salt(csprng)?;
                let salted_element = sd_claims.push_ref(SaltedElementRef { salt, value: original_value })?;
                let digest = digest(salted_element)?;
                let rce = RedactedClaimElement::from(&digest[..]);
                *value = Value::serialized(&rce)?;
            }
        }
        value => {
            match parent_ctx {
                Some((parent_label, rcks)) => {
                    // ... in a Mapping. So we insert it in the disclosures and push the digest to it's parent 'redacted_claim_keys'

                    // unwrap tagged values
                    let value = match value {
                        Value::Tag(tag, value) if *tag == TO_BE_REDACTED_TAG => value,
                        value => value,
                    };

                    if let Some(parent_label) = parent_label.untag() {
                        let salt = &new_salt(csprng)?;
                        let disclosure = SaltedClaimRef {
                            salt,
                            claim: &parent_label,
                            value,
                        };
                        let salted_claim = sd_claims.push_ref(disclosure)?;
                        rcks.push(&digest(salted_claim)?[..]);
                    }
                }
                None => {
                    if let Value::Tag(TO_BE_REDACTED_TAG, original_value) = value {
                        // ... in an Array. So we insert it in the disclosures and replace the element with its digest in the array
                        let salt = &new_salt(csprng)?;
                        let disclosure = SaltedElementRef { salt, value: original_value };
                        let salted_element = sd_claims.push_ref(disclosure)?;
                        let digest = digest(salted_element)?;
                        let rce = RedactedClaimElement::from(&digest[..]);
                        *value = Value::serialized(&rce)?;
                    }
                }
            }
        }
    }
    Ok(())
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
    use crate::spec::sd;
    use ciborium::cbor;
    use esdicawt_spec::{
        REDACTED_CLAIM_ELEMENT_TAG,
        blinded_claims::{Decoy, SaltedClaim, SaltedElement},
    };
    use rand_chacha::rand_core::SeedableRng as _;
    use sha2::Digest as _;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[allow(clippy::cognitive_complexity)]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_primitive_claim_in_mapping() {
        let payload = Value::Map(vec![
            (sd(Value::Text("a".into())), Value::Integer(1.into())),
            (sd(Value::Integer(2.into())), Value::Text("b".into())),
            (sd(Value::Integer(3.into())), Value::Null),
            (sd(Value::Integer(4.into())), Value::Bool(false)),
            (sd(Value::Integer(5.into())), Value::Float(14.3)),
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
        assert!(matches!(&d1.name, ClaimName::Text(n) if n == "a"));
        assert_eq!(d1.value, 1);
        assert!(rck_contains_digest(&rck, &d1));

        let d2 = d2.deserialized::<SaltedClaim<String>>().unwrap();
        assert!(matches!(&d2.name, ClaimName::Integer(n) if *n == 2));
        assert_eq!(&d2.value, "b");
        assert!(rck_contains_digest(&rck, &d2));

        let d3 = d3.deserialized::<SaltedClaim<Option<u8>>>().unwrap();
        assert!(matches!(&d3.name, ClaimName::Integer(n) if *n == 3));
        assert_eq!(d3.value, None);
        assert!(rck_contains_digest(&rck, &d3));

        let d4 = d4.deserialized::<SaltedClaim<bool>>().unwrap();
        assert!(matches!(&d4.name, ClaimName::Integer(n) if *n == 4));
        assert!(!d4.value);
        assert!(rck_contains_digest(&rck, &d4));

        let d5 = d5.deserialized::<SaltedClaim<f64>>().unwrap();
        assert!(matches!(&d5.name, ClaimName::Integer(n) if *n == 5));
        assert_eq!(d5.value, 14.3);
        assert!(rck_contains_digest(&rck, &d5));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_array() {
        let payload = Value::Map(vec![(
            sd(Value::Integer(1.into())),
            Value::Array(vec![sd(Value::Text("a".into())), sd(Value::Text("b".into()))]),
        )]);
        let (payload, [d1, d2, d3]) = _redact(payload);

        // --- altered payload ---
        let rck = get_redacted_claim_keys::<1>(&payload);
        let payload = payload.as_map().unwrap();

        // all redacted claims have been removed
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(1).unwrap()));

        let d3 = d3.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        assert!(matches!(&d3.name, ClaimName::Integer(n) if *n == 1));
        assert!(rck_contains_digest(&rck, &d3));

        // verify that the disclosure of mapping claim '1' contains a redacted array which itself
        // contains the redacted in place elements "a" and "b"
        let [a, b]: [RedactedClaimElement; 2] = d3.value.try_into().unwrap();
        assert_eq!(Value::serialized(&a).unwrap(), element_digest(&d1));
        assert_eq!(Value::serialized(&b).unwrap(), element_digest(&d2));

        let d1 = d1.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d1.value, "a".to_string());

        let d2 = d2.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d2.value, "b".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_array_nested() {
        let payload = Value::Map(vec![(
            sd(Value::Integer(1.into())),
            Value::Array(vec![sd(Value::Array(vec![sd(Value::Text("a".into())), sd(Value::Text("b".into()))]))]),
        )]);
        let (payload, [d1, d2, d3, d4]) = _redact(payload);

        // --- altered payload ---
        let rck = get_redacted_claim_keys::<1>(&payload);
        let payload = payload.as_map().unwrap();

        // all redacted claims have been removed
        assert!(!payload.iter().any(|(k, _)| k == &cbor!(1).unwrap()));

        let d4 = d4.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        assert!(matches!(&d4.name, ClaimName::Integer(n) if *n == 1));
        assert!(rck_contains_digest(&rck, &d4));

        // verify that the disclosure of mapping claim '1' contains a redacted array which itself
        // contains a redacted array which itself contains the redacted in place elements "a" & "b"
        let [nested_array]: [RedactedClaimElement; 1] = d4.value.try_into().unwrap();
        assert_eq!(Value::serialized(&nested_array).unwrap(), element_digest(&d3));

        let d3 = d3.deserialized::<SaltedElement<Vec<RedactedClaimElement>>>().unwrap();
        let [a, b]: [RedactedClaimElement; 2] = d3.value.try_into().unwrap();
        assert_eq!(Value::serialized(&a).unwrap(), element_digest(&d1));
        assert_eq!(Value::serialized(&b).unwrap(), element_digest(&d2));

        let d1 = d1.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d1.value, "a".to_string());

        let d2 = d2.deserialized::<SaltedElement<String>>().unwrap();
        assert_eq!(d2.value, "b".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_nested_mapping() {
        let payload = Value::Map(vec![(
            sd(Value::Integer(0.into())),
            Value::Map(vec![(sd(Value::Integer(1.into())), Value::Text("a".into()))]),
        )]);
        let (payload, [d1, d0]) = _redact(payload);

        // --- depth 0 ---
        let rck0 = get_redacted_claim_keys::<1>(&payload);
        let payload0 = payload.as_map().unwrap();
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(0).unwrap()));

        // --- disclosures ---
        let d0 = d0.deserialized::<SaltedClaim<Value>>().unwrap();
        assert!(matches!(&d0.name, ClaimName::Integer(i) if *i == 0));
        assert!(rck_contains_digest(&rck0, &d0));

        // --- depth 1 ---
        let payload1 = d0.value;
        let rck1 = get_redacted_claim_keys::<1>(&payload1);
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(1).unwrap()));
        assert!(rck_contains_digest(&rck1, &d1));

        // --- disclosures ---
        let d1 = d1.deserialized::<SaltedClaim<String>>().unwrap();
        assert!(matches!(&d1.name, ClaimName::Integer(i) if *i == 1));
        assert_eq!(d1.value, "a".to_string());
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_redact_mapping_nested_in_array() {
        let payload = Value::Map(vec![(
            sd(Value::Integer(0.into())),
            Value::Array(vec![sd(Value::Map(vec![(sd(Value::Integer(1.into())), Value::Integer(2.into()))]))]),
        )]);
        let (payload, [d2, d1, d0]) = _redact(payload);

        // --- depth 0 ---
        let rck0 = get_redacted_claim_keys::<1>(&payload);
        assert!(rck_contains_digest(&rck0, &d0));

        let payload0 = payload.as_map().unwrap();
        assert!(!payload0.iter().any(|(k, _)| k == &cbor!(0).unwrap()));

        // --- depth 2 ---
        let d2 = d2.deserialized::<SaltedClaim<u64>>().unwrap();
        assert!(matches!(&d2.name, ClaimName::Integer(n) if *n == 1));
        assert_eq!(d2.value, 2);

        // --- depth 1 ---
        let d1 = d1.deserialized::<SaltedElement<Value>>().unwrap();
        let rck1 = get_redacted_claim_keys::<1>(&d1.value);
        let payload1 = d1.value.as_map().unwrap();
        assert!(!payload1.iter().any(|(k, _)| k == &cbor!(1).unwrap()));
        assert!(rck_contains_digest(&rck1, &d2));

        // --- depth 0, again ---
        let d0 = d0.deserialized::<SaltedClaim<Vec<RedactedClaimElement>>>().unwrap();
        assert!(matches!(&d0.name, ClaimName::Integer(n) if *n == 0));

        let [mapping12]: [RedactedClaimElement; 1] = d0.value.try_into().unwrap();
        assert_eq!(Value::serialized(&mapping12).unwrap(), element_digest(&d1));
    }

    fn _redact<const N: usize>(mut payload: Value) -> (Value, [Value; N]) {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut sd_claims = SaltedArray::default();

        redact_value::<Error, sha2::Sha256>(&mut payload, &mut rng, &mut sd_claims, None).unwrap();

        for d in &sd_claims.0 {
            if let Ok(d) = d.deserialized::<SaltedClaim<Value>>() {
                assert_eq!(d.salt.0.len(), Salt::SIZE);
            } else if let Ok(d) = d.deserialized::<SaltedElement<Value>>() {
                assert_eq!(d.salt.0.len(), Salt::SIZE);
            } else if let Ok(d) = d.deserialized::<Decoy>() {
                assert_eq!(d.salt.0.len(), Salt::SIZE);
            }
        }

        let size = sd_claims.0.len();
        let disclosures = sd_claims.0.try_into().unwrap_or_else(|_| panic!("Expected {N} disclosures but got {size}"));

        (payload, disclosures)
    }

    fn rck_contains_digest(rck: &[Value], disclosure: &impl CwtAny) -> bool {
        let digest = &claim_digest(disclosure)[..];
        rck.iter().map(|r| r.as_bytes().unwrap()).any(|r| r == digest)
    }

    fn claim_digest(disclosure: &impl CwtAny) -> Vec<u8> {
        let cbor = disclosure.to_cbor_bytes().unwrap();
        sha2::Sha256::digest(cbor).to_vec()
    }

    fn element_digest(disclosure: &impl CwtAny) -> Value {
        Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, Box::new(Value::Bytes(claim_digest(disclosure))))
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
