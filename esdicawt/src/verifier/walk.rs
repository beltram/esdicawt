use crate::{
    SdCwtVerifierError, SdCwtVerifierResult,
    spec::{
        CwtAny,
        blinded_claims::{SaltedArrayToVerify, SaltedClaim, SaltedElement, SaltedEntry},
        redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
    },
};
use ciborium::Value;
use std::rc::Rc;

// wrapping "_walk" is required for fallible recursion
pub fn walk_payload<E>(hasher: Rc<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayToVerify) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    _walk(hasher, payload, disclosures)
}

#[tailcall::tailcall]
fn _walk<E>(hasher: Rc<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayToVerify) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    match payload {
        Value::Map(mapping) => {
            let pos = mapping.iter().position(|(k, _)| matches!(k, Value::Simple(RedactedClaimKeys::CWT_LABEL)));

            if let Some(pos) = pos {
                let (_, rcks) = mapping.swap_remove(pos);
                let rcks = rcks.deserialized::<RedactedClaimKeys>()?;
                for rck in rcks {
                    if let Some(pos) = disclosures.iter().position(|(salted, redacted)| {
                        redacted.or_init_detached_hasher(salted.as_ref(), &hasher);
                        *redacted == rck
                    }) {
                        let (mut found, _) = disclosures.swap_remove(pos);
                        match found.to_mut() {
                            SaltedEntry::Claim(SaltedClaim { name, value, .. }) => {
                                if value.is_map() || value.is_array() {
                                    walk_payload(hasher.clone(), value, disclosures)?;
                                }
                                let key = name.to_cbor_value()?;
                                if mapping.iter().any(|(k, _)| k == &key) {
                                    return Err(SdCwtVerifierError::DuplicateMapKeys);
                                }
                                mapping.push((key, core::mem::replace(value, Value::Null)))
                            }
                            SaltedEntry::Decoy(_) => {} // nothing to do, validity of hash already checked
                            SaltedEntry::Element(_) => return Err(SdCwtVerifierError::MalformedSdCwt("'redacted_claim_keys' must not contain redacted elements")),
                        }
                    }
                }
            }

            for (_, v) in mapping {
                walk_payload(hasher.clone(), v, disclosures)?;
            }
        }
        Value::Array(array) => {
            for element in array {
                // not all the array elements are redacted, we might have partial redactions
                let Ok(redacted_element) = element.deserialized::<RedactedClaimElement>() else {
                    walk_payload(hasher.clone(), element, disclosures)?;
                    continue;
                };

                if let Some(pos) = disclosures.iter().position(|(salted, redacted)| {
                    redacted.or_init_detached_hasher(salted.as_ref(), &hasher);
                    *redacted == redacted_element
                }) {
                    let (mut found, _) = disclosures.swap_remove(pos);
                    match found.to_mut() {
                        SaltedEntry::Element(SaltedElement { value, .. }) => {
                            if value.is_map() || value.is_array() {
                                walk_payload(hasher.clone(), value, disclosures)?;
                            }
                            *element = core::mem::replace(value, Value::Null);
                        }
                        SaltedEntry::Decoy(_) => {} // nothing to do, validity of hash already checked
                        SaltedEntry::Claim(_) => return Err(SdCwtVerifierError::MalformedSdCwt("a array must not contain a redacted claim key")),
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}
