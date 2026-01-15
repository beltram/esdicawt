use crate::{SdCwtVerifierError, SdCwtVerifierResult};
use ciborium::Value;
use esdicawt_spec::{
    CwtAny,
    blinded_claims::{Salted, SaltedArrayToVerify, SaltedClaim, SaltedElement},
    redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
};

// wrapping "_walk" is required for fallible recursion
pub fn walk_payload<E>(hasher: Box<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayToVerify) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    _walk(hasher, payload, disclosures)
}

#[tailcall::tailcall]
fn _walk<E>(hasher: Box<dyn digest::DynDigest>, payload: &mut Value, disclosures: &mut SaltedArrayToVerify) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    match payload {
        Value::Map(mapping) => {
            let pos = mapping.iter().position(|(k, _)| match k {
                Value::Simple(i) => *i == RedactedClaimKeys::CWT_LABEL,
                _ => false,
            });

            if let Some(pos) = pos {
                let (_, rcks) = mapping.swap_remove(pos);
                let rcks = rcks.deserialized::<RedactedClaimKeys>()?;
                for rck in rcks.iter() {
                    if let Some(pos) = disclosures.iter_mut().position(|(salted, digest)| {
                        match digest {
                            Some(digest) => **digest == **rck,
                            entry => {
                                let Salted::Claim(sc) = salted.as_ref() else { return false };
                                let Ok(cbor_bytes) = sc.to_cbor_bytes() else { return false };

                                // box_clone clones the hasher and his state.
                                // Otherwise, this code would not be thread safe as different threads could share the same hasher state.
                                let mut h = hasher.box_clone();
                                h.as_mut().update(&cbor_bytes[..]);
                                let digest = h.finalize();
                                entry.replace(digest.to_vec());
                                *digest.as_ref() == **rck
                            }
                        }
                    }) {
                        let (mut found, _) = disclosures.swap_remove(pos);
                        match found.to_mut() {
                            Salted::Claim(SaltedClaim { name, value, .. }) => {
                                if value.is_map() || value.is_array() {
                                    walk_payload(hasher.clone(), value, disclosures)?;
                                }
                                // TODO: verify the key ('name') is not already present in the mapping
                                mapping.push((name.to_cbor_value()?, value.clone()))
                            }
                            Salted::Decoy(_) => {} // nothing to do, validity of hash already checked
                            Salted::Element(_) => return Err(SdCwtVerifierError::MalformedSdCwt("'redacted_claim_keys' must not contain redacted elements")),
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

                if let Some(pos) = disclosures.iter_mut().position(|(salted, digest)| {
                    match digest {
                        Some(digest) => **digest == *redacted_element,
                        entry => {
                            let Salted::Element(sc) = salted.as_ref() else { return false };
                            let Ok(cbor_bytes) = sc.to_cbor_bytes() else { return false };

                            // box_clone clones the hasher and his state.
                            // Otherwise, this code would not be thread safe as different threads could share the same hasher state.
                            let mut h = hasher.box_clone();
                            h.as_mut().update(&cbor_bytes[..]);
                            let digest = h.finalize();
                            entry.replace(digest.to_vec());
                            *digest.as_ref() == *redacted_element
                        }
                    }
                }) {
                    let (mut found, _) = disclosures.swap_remove(pos);
                    match found.to_mut() {
                        Salted::Element(SaltedElement { value, .. }) => {
                            if value.is_map() || value.is_array() {
                                walk_payload(hasher.clone(), value, disclosures)?;
                            }
                            *element = value.clone()
                        }
                        Salted::Decoy(_) => {} // nothing to do, validity of hash already checked
                        Salted::Claim(_) => return Err(SdCwtVerifierError::MalformedSdCwt("a array must not contain a redacted claim key")),
                    }
                }
            }
        }
        _ => {}
    }
    Ok(())
}
