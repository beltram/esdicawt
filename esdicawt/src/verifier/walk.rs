use crate::{
    SdCwtVerifierError, SdCwtVerifierResult,
    spec::{
        CwtAny, REDACTED_CLAIM_ELEMENT_TAG,
        blinded_claims::{SaltedClaim, SaltedElement, SaltedEntry},
        is_safe_tag,
        redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
    },
};
use ciborium::Value;
use esdicawt_spec::{SdCwtClaim, blinded_claims::SaltedArrayHashing};
use std::{collections::HashSet, rc::Rc};

/// Puts back the disclosed claims in the payload, from its root
pub fn walk_payload<E>(hasher: Rc<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayHashing) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    _walk(hasher, payload, disclosures, true)
}

#[tailcall::tailcall]
fn _walk<E>(hasher: Rc<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayHashing, root: bool) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    match payload {
        Value::Map(mapping) => {
            let pos = mapping.iter().position(|(k, _)| matches!(k, Value::Simple(RedactedClaimKeys::CWT_LABEL)));

            if let Some(pos) = pos {
                let (_, rcks) = mapping.swap_remove(pos);
                let rcks = rcks.deserialized::<RedactedClaimKeys>()?;

                // sized upfront to avoid rehashing/reallocating while disclosed claims are added
                let mut keys = HashSet::with_capacity(mapping.len() + rcks.0.len());
                mapping.reserve(rcks.0.len());

                // prevents linear lookup when trying to catch `DuplicateMapKeys`
                keys.extend(mapping.iter().filter_map(|(k, _)| SdCwtClaim::from_cbor_value(k).ok()));

                for rck in rcks {
                    if let Some(found) = disclosures.remove_lazy(&rck, &hasher) {
                        match found.into_owned() {
                            SaltedEntry::Claim(SaltedClaim { name, mut value, .. }) => {
                                if root && name.is_never_redacted() {
                                    return Err(SdCwtVerifierError::MustNotBeRedacted(name));
                                }
                                walk_nested(hasher.clone(), &mut value, disclosures)?;
                                let label = Value::from(&name);
                                if !keys.insert(name) {
                                    return Err(SdCwtVerifierError::DuplicateMapKeys);
                                }
                                mapping.push((label, value))
                            }
                            SaltedEntry::Decoy(_) => {} // nothing to do, validity of hash already checked
                            SaltedEntry::Element(_) => return Err(SdCwtVerifierError::MalformedSdCwt("'redacted_claim_keys' must not contain redacted elements")),
                        }
                    }
                }
            }

            for (_, v) in mapping {
                walk_nested(hasher.clone(), v, disclosures)?;
            }
        }
        Value::Array(array) => {
            for element in array.iter_mut() {
                // not all the array elements are redacted, we might have partial redactions
                let Ok(redacted_element) = element.deserialized::<RedactedClaimElement>() else {
                    walk_nested(hasher.clone(), element, disclosures)?;
                    continue;
                };

                if let Some(mut found) = disclosures.remove_lazy(&redacted_element, &hasher) {
                    match found.to_mut() {
                        SaltedEntry::Element(SaltedElement { value, .. }) => {
                            walk_nested(hasher.clone(), value, disclosures)?;
                            *element = core::mem::replace(value, Value::Null);
                        }
                        SaltedEntry::Decoy(_) => {} // nothing to do, validity of hash already checked
                        SaltedEntry::Claim(_) => return Err(SdCwtVerifierError::MalformedSdCwt("a array must not contain a redacted claim key")),
                    }
                }
            }

            // the remaining redacted elements are either decoys or not disclosed, so they are removed
            // see step 10 of https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-kbt-and-sd-cwt-verifier-val
            array.retain(|element| !matches!(element, Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, _)));
        }
        Value::Tag(tag, inner) if is_safe_tag(*tag) => walk_nested(hasher, inner, disclosures)?,
        _ => {}
    }
    Ok(())
}

// wrapping "_walk" is required for fallible recursion
fn walk_nested<E>(hasher: Rc<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayHashing) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    _walk(hasher, payload, disclosures, false)
}
