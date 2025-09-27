use crate::{SdCwtVerifierError, SdCwtVerifierResult};
use ciborium::Value;
use esdicawt_spec::{
    blinded_claims::{Salted, SaltedClaim, SaltedElement},
    redacted_claims::{RedactedClaimElement, RedactedClaimKeys},
};
use std::collections::HashMap;

// wrapping "_walk" is required for fallible recursion
pub fn walk_payload<E>(payload: &mut Value, disclosures: &mut HashMap<Vec<u8>, &mut Salted<Value>>) -> SdCwtVerifierResult<(), E>
where
    E: core::error::Error + Send + Sync,
{
    _walk(payload, disclosures)
}

#[tailcall::tailcall]
fn _walk<E>(payload: &mut Value, disclosures: &mut HashMap<Vec<u8>, &mut Salted<Value>>) -> SdCwtVerifierResult<(), E>
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
                let (_, rcks) = mapping.remove(pos);
                let rcks = rcks.deserialized::<RedactedClaimKeys>()?;
                for rck in rcks.iter() {
                    if let Some(salted) = disclosures.remove(rck.as_ref()) {
                        match salted {
                            Salted::Claim(SaltedClaim { name, value, .. }) => {
                                if value.is_map() || value.is_array() {
                                    walk_payload(value, disclosures)?;
                                }
                                // TODO: verify the key ('name') is not already present in the mapping
                                let name = Value::serialized(&name)?;
                                mapping.push((name, value.clone()))
                            }
                            Salted::Decoy(_) => {} // nothing to do, validity of hash already checked
                            Salted::Element(_) => return Err(SdCwtVerifierError::MalformedSdCwt("'redacted_claim_keys' must not contain redacted elements")),
                        }
                    } else {
                        return Err(SdCwtVerifierError::MalformedSdCwt("Redacted claim not in disclosures"));
                    }
                }
            }
        }
        Value::Array(array) => {
            for element in array {
                // not all the array elements are redacted, we might have partial redactions
                let Ok(e) = element.deserialized::<RedactedClaimElement>() else {
                    walk_payload(element, disclosures)?;
                    continue;
                };
                if let Some(salted) = disclosures.remove(&*e) {
                    match salted {
                        Salted::Element(SaltedElement { value, .. }) => {
                            if value.is_map() || value.is_array() {
                                walk_payload(value, disclosures)?;
                            }
                            *element = value.clone()
                        }
                        Salted::Decoy(_) => {} // nothing to do, validity of hash already checked
                        Salted::Claim(_) => return Err(SdCwtVerifierError::MalformedSdCwt("a array must not contain a redacted claim key")),
                    }
                } else {
                    return Err(SdCwtVerifierError::MalformedSdCwt("Redacted element not in disclosures"));
                }
            }
        }
        _ => {}
    }
    Ok(())
}
