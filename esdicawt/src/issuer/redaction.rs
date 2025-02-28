use crate::SdCwtIssuerError;
use ciborium::Value;
use esdicawt_spec::{
    ClaimName, CwtAny, Salt,
    blinded_claims::{SaltedArray, SaltedClaimRef, SaltedElementRef},
    redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
};
use std::ops::DerefMut;

/// Redacts the claims in this Value by recursively traversing, depth-first the ClaimSet
pub fn redact<E, Hasher>(csprng: &mut dyn rand_core::CryptoRngCore, mut disclosable_claims: &mut Value) -> Result<SaltedArray, SdCwtIssuerError<E>>
where
    E: std::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    let mut sd_claims = SaltedArray::default();
    disclosable_claims.redact::<E, Hasher>(csprng, &mut sd_claims, None, true)?;
    Ok(sd_claims)
}

trait Redact {
    fn redact<E, Hasher>(
        &mut self,
        csprng: &mut dyn rand_core::CryptoRngCore,
        sd_claims: &mut SaltedArray,
        mapping_ctx: Option<(&ClaimName, &mut RedactedClaimKeys)>,
        root: bool,
    ) -> Result<(), SdCwtIssuerError<E>>
    where
        E: std::error::Error + Send + Sync,
        Hasher: digest::Digest;
}

impl Redact for &mut Value {
    // wrapping "_redact" is required for fallible recursion
    fn redact<E, Hasher>(
        &mut self,
        csprng: &mut dyn rand_core::CryptoRngCore,
        sd_claims: &mut SaltedArray,
        mapping_ctx: Option<(&ClaimName, &mut RedactedClaimKeys)>,
        root: bool,
    ) -> Result<(), SdCwtIssuerError<E>>
    where
        E: std::error::Error + Send + Sync,
        Hasher: digest::Digest,
    {
        _redact::<E, Hasher>(self, csprng, sd_claims, mapping_ctx, root)
    }
}

#[tailcall::tailcall]
fn _redact<E, Hasher>(
    mut value: &mut Value,
    csprng: &mut dyn rand_core::CryptoRngCore,
    sd_claims: &mut SaltedArray,
    mapping_ctx: Option<(&ClaimName, &mut RedactedClaimKeys)>,
    root: bool,
) -> Result<(), SdCwtIssuerError<E>>
where
    E: std::error::Error + Send + Sync,
    Hasher: digest::Digest,
{
    let digest = |v: &Value| Result::<_, SdCwtIssuerError<E>>::Ok(Hasher::digest(&v.to_cbor_bytes()?));
    match value.deref_mut() {
        value @ Value::Array(_) => {
            // SAFETY: we already verified it's an array
            let array = value.as_array_mut().unwrap();

            for mut element in array.iter_mut() {
                element.redact::<E, Hasher>(csprng, sd_claims, None, false)?;
            }
            // redact the array itself
            let salt = &new_salt(csprng)?;
            if let Some((claim, rcks)) = mapping_ctx {
                let salted_claim = sd_claims.push_ref(SaltedClaimRef { salt, claim, value })?;
                rcks.push(&digest(salted_claim)?[..]);
            } else {
                let salted_element = sd_claims.push_ref(SaltedElementRef { salt, value })?;
                let digest = digest(salted_element)?;
                let rce = RedactedClaimElement::from(&digest[..]);
                *value = Value::serialized(&rce)?;
            }
        }
        value @ Value::Map(_) => {
            // SAFETY: we already verified it's a mapping
            let mapping = value.as_map_mut().unwrap();

            let mut rcks = RedactedClaimKeys::with_capacity(mapping.len());
            for (claim, mut claim_value) in mapping.drain(..) {
                let claim = claim.try_into().map_err(|_| SdCwtIssuerError::CwtError("FIXME: once we support depths"))?;
                (&mut claim_value).redact::<E, Hasher>(csprng, sd_claims, Some((&claim, &mut rcks)), false)?;
            }

            mapping.push(rcks.into_map_entry()?);

            match (mapping_ctx, root) {
                (None, true) => {} // no parent so nothing to do
                // we are already in a Mapping so we'll nest this Mapping in his parent
                (Some((claim, rcks)), _) => {
                    let salt = &new_salt(csprng)?;
                    let disclosure = SaltedClaimRef { salt, claim, value };
                    let salted_claim = sd_claims.push_ref(disclosure)?;
                    rcks.push(&digest(salted_claim)?[..]);
                }
                _ => {
                    // we are in an array so we replace the element with this redacted mapping
                    let salt = &new_salt(csprng)?;
                    let salted_claim = sd_claims.push_ref(SaltedElementRef { salt, value })?;
                    let digest = digest(salted_claim)?;
                    let rce = RedactedClaimElement::from(&digest[..]);
                    *value = Value::serialized(&rce)?;
                }
            }
        }
        // primitive type...
        value => match mapping_ctx {
            // ... in a Mapping. So we insert it in the disclosures and push the digest to it's parent 'redacted_claim_keys'
            Some((claim, rcks)) => {
                let salt = &new_salt(csprng)?;
                let salted_claim = sd_claims.push_ref(SaltedClaimRef { salt, claim, value })?;
                rcks.push(&digest(salted_claim)?[..]);
            }
            // ... in an Array. So we insert it in the disclosures and replace the element with its digest in the array
            None => {
                let salt = &new_salt(csprng)?;
                let salted_element = sd_claims.push_ref(SaltedElementRef { salt, value })?;
                let digest = digest(salted_element)?;
                let rce = RedactedClaimElement::from(&digest[..]);
                *value = Value::serialized(&rce)?;
            }
        },
    }

    Ok(())
}

fn new_salt<E>(csprng: &mut dyn rand_core::CryptoRngCore) -> Result<Salt, SdCwtIssuerError<E>>
where
    E: std::error::Error + Send + Sync,
{
    let mut salt = Salt::empty();
    csprng.try_fill_bytes(&mut *salt)?;
    Ok(salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciborium::cbor;
    use esdicawt_spec::{
        REDACTED_CLAIM_ELEMENT_TAG,
        blinded_claims::{Decoy, SaltedClaim, SaltedElement},
    };
    use rand_chacha::rand_core::SeedableRng as _;
    use sha2::Digest as _;

    #[test]
    #[allow(clippy::cognitive_complexity)]
    fn should_redact_primitive_claim_in_mapping() {
        let payload = cbor!({
            "a" => 1,
            2 => "b",
            3 => null,
            4 => false,
            5 => 14.3,
        });
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
    fn should_redact_array() {
        let payload = cbor!({ 1 => ["a", "b"] });
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
    fn should_redact_array_nested() {
        let payload = cbor!({ 1 => [["a", "b"]] });
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
    fn should_redact_nested_mapping() {
        let payload = cbor!({ 0 => { 1 => "a" } });
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
    fn should_redact_mapping_nested_in_array() {
        let payload = cbor!({ 0 => [{ 1 => 2 }] });
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

    fn _redact<const N: usize>(payload: Result<Value, ciborium::value::Error>) -> (Value, [Value; N]) {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
        let mut payload = payload.unwrap();
        let mut sd_claims = SaltedArray::default();

        (&mut payload).redact::<Error, sha2::Sha256>(&mut rng, &mut sd_claims, None, true).unwrap();

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
        let (_, rck) = payload.iter().find(|(k, _)| k.as_integer() == Some(RedactedClaimKeys::CWT_KEY.into())).unwrap();
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
