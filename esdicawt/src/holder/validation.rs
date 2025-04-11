use ciborium::Value;
use esdicawt_spec::{REDACTED_CLAIM_ELEMENT_TAG, blinded_claims::Salted, redacted_claims::RedactedClaimKeys};
use std::{borrow::Cow, collections::HashMap};

#[derive(Default, Debug, Clone)]
pub struct HolderValidationParams<'a> {
    pub expected_subject: Option<&'a str>,
    pub expected_issuer: Option<&'a str>,
    pub expected_audience: Option<&'a str>,
    pub expected_cnonce: Option<&'a [u8]>,
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    /// for testing
    pub artificial_time: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum SdCwtHolderValidationError<CustomError: Send + Sync> {
    #[error("Expected sub to be '{expected}' but was '{actual}'")]
    SubMismatch { expected: String, actual: String },
    #[error("Expected issuer to be '{expected}' but was '{actual}'")]
    IssuerMismatch { expected: String, actual: String },
    #[error("Expected audience to be '{expected}' but was '{actual}'")]
    AudienceMismatch { expected: String, actual: String },
    #[error("Expected cnonce to be '{expected:x?}' but was '{actual:x?}'")]
    CnonceMismatch { expected: Vec<u8>, actual: Vec<u8> },
    #[error("Expected key confirmation mismatches")]
    VerifyingKeyMismatch,
    #[error("A disclosure in the payload is not mentioned in the unprotected header")]
    DisclosureNotFound,
    #[error("Expected to find {expected} disclosures, found {actual}")]
    OrphanDisclosure { expected: usize, actual: usize },
    #[error(transparent)]
    CborDeserializeError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    SignatureError(#[from] signature::Error),
    #[error("{0}")]
    SpecError(&'static str),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error(transparent)]
    CustomError(CustomError),
}

// wrapping "_validate" is required for fallible recursion
pub fn validate_disclosures<E>(payload: &Value, disclosures: &HashMap<Vec<u8>, Cow<Salted<Value>>>) -> Result<usize, SdCwtHolderValidationError<E>>
where
    E: core::error::Error + Send + Sync,
{
    _validate(payload, disclosures)
}

#[tailcall::tailcall]
fn _validate<E>(payload: &Value, disclosures: &HashMap<Vec<u8>, Cow<Salted<Value>>>) -> Result<usize, SdCwtHolderValidationError<E>>
where
    E: core::error::Error + Send + Sync,
{
    let mut count = 0;
    match payload {
        Value::Map(mapping) => {
            for entry in mapping {
                match entry {
                    (Value::Simple(RedactedClaimKeys::CWT_LABEL), rcks) => {
                        let rcks = rcks.deserialized::<RedactedClaimKeys>()?;
                        for rck in rcks.iter() {
                            let Some(d) = disclosures.get(rck.as_ref()) else {
                                return Err(SdCwtHolderValidationError::DisclosureNotFound);
                            };
                            if let Some(v) = d.as_ref().value().filter(|v| v.is_map() || v.is_array()) {
                                count += validate_disclosures(v, disclosures)?
                            }
                        }
                        count += rcks.len();
                    }
                    (_, v) if v.is_map() || v.is_array() => count += validate_disclosures(v, disclosures)?,
                    _ => {}
                }
            }
        }
        Value::Array(array) => {
            for element in array {
                match element {
                    Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, rce) => {
                        let rce = rce.as_bytes().ok_or(SdCwtHolderValidationError::SpecError("RedactedClaimElement should be a bstr"))?;
                        let Some(d) = disclosures.get(rce) else {
                            return Err(SdCwtHolderValidationError::DisclosureNotFound);
                        };
                        count += 1;
                        if let Some(v) = d.as_ref().value().filter(|v| v.is_map() || v.is_array()) {
                            count += validate_disclosures(v, disclosures)?
                        }
                    }
                    e if e.is_map() || e.is_array() => count += validate_disclosures(e, disclosures)?,
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use crate::{
        HolderValidationParams, IssuerParams, SdCwtHolderError, SdCwtHolderValidationError,
        blinded_claims::Decoy,
        holder::Holder,
        issuer::Issuer,
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use ciborium::{Value, cbor};
    use esdicawt::Salt;
    use esdicawt_spec::{
        ClaimName, CwtAny,
        blinded_claims::{Salted, SaltedElement},
        issuance::SdCwtIssuedTagged,
        sd,
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng as _;

    #[test]
    fn should_fail_when_claims_mismatch() {
        let mut csprng = ChaCha20Rng::from_entropy();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer_verifying_key = issuer_signing_key.verifying_key();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let holder = Ed25519Holder::<Value>::new(holder_signing_key.clone());

        let mut issuer_params = default_issuer_params(&holder_signing_key, None);
        issuer_params.issuer = "iss-a";
        issuer_params.subject = Some("sub-a");
        issuer_params.audience = Some("aud-a");
        issuer_params.cnonce = Some(b"cnonce-a");

        let sd_cwt = issuer.issue_cwt(&mut csprng, issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let mut validation_params = HolderValidationParams {
            expected_subject: Some("sub-a"),
            expected_issuer: Some("iss-a"),
            expected_audience: Some("aud-a"),
            expected_cnonce: Some(b"cnonce-a"),
            leeway: Default::default(),
            artificial_time: None,
        };

        // should work by default
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === sub mismatch ===
        validation_params.expected_subject.replace("sub-b");
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::SubMismatch { expected, actual })) if &expected == "sub-b" && &actual == "sub-a"
        ));
        // works with right expectation
        validation_params.expected_subject.replace("sub-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === issuer mismatch ===
        validation_params.expected_issuer.replace("iss-b");
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::IssuerMismatch { expected, actual })) if &expected == "iss-b" && &actual == "iss-a"
        ));
        // works with right expectation
        validation_params.expected_issuer.replace("iss-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === audience mismatch ===
        validation_params.expected_audience.replace("aud-b");
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::AudienceMismatch { expected, actual })) if &expected == "aud-b" && &actual == "aud-a"
        ));
        // works with right expectation
        validation_params.expected_audience.replace("aud-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === cnonce mismatch ===
        validation_params.expected_cnonce.replace(b"cnonce-b");
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::CnonceMismatch { expected, actual })) if &expected == b"cnonce-b" && &actual == b"cnonce-a"
        ));
        // works with right expectation
        validation_params.expected_cnonce.replace(b"cnonce-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === verifying key mismatch
        let holder_bis = Ed25519Holder::<Value>::new(ed25519_dalek::SigningKey::generate(&mut csprng));
        assert!(matches!(
            holder_bis.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::VerifyingKeyMismatch))
        ));
    }

    #[test]
    fn should_fail_when_disclosures_invalid() {
        let mut csprng = ChaCha20Rng::from_entropy();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer_verifying_key = issuer_signing_key.verifying_key();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let holder = Ed25519Holder::<Value>::new(holder_signing_key.clone());

        let payload = cbor!({
            sd!(42) => "a",
            sd!(43) => { sd!(44) => 4 },
            sd!(45) => [ sd!(46) ],
            sd!(47) => [sd!(Value::Array(vec![sd!(48)]))],
        })
        .unwrap();

        let issuer_params = default_issuer_params(&holder_signing_key, Some(payload));
        let sd_cwt = issuer.issue_cwt(&mut csprng, issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let sd_cwt_tagged = SdCwtIssuedTagged::<Value, sha2::Sha256>::from_cbor_bytes(&sd_cwt).unwrap();

        // remove disclosure of the map
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .0
            .sd_unprotected
            .sd_claims
            .0
            .retain(|d| !matches!(d.clone_value().unwrap(), c if c.name() == Some(&ClaimName::Integer(42))));
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));

        // remove disclosure of the inner map
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .0
            .sd_unprotected
            .sd_claims
            .0
            .retain(|d| !matches!(d.clone_value().unwrap(), c if c.name() == Some(&ClaimName::Integer(44))));
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));

        // remove disclosure of the array element
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .0
            .sd_unprotected
            .sd_claims
            .0
            .retain(|d| !matches!(d.clone_value().unwrap(), c if c.value() == Some(&cbor!(46).unwrap())));
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));

        // remove disclosure of the nested array element
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .0
            .sd_unprotected
            .sd_claims
            .0
            .retain(|d| !matches!(d.clone_value().unwrap(), c if c.value() == Some(&cbor!(48).unwrap())));
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));

        // adding extra disclosure
        let mut sd_cwt = sd_cwt_tagged.clone();
        let extra = Salted::Element(SaltedElement {
            value: cbor!("a").unwrap(),
            salt: Salt::empty(),
        });
        sd_cwt.0.sd_unprotected.sd_claims.0.push(extra.into());
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure { expected, actual }))
            if expected == 8 && actual == 9
        ));

        // adding extra decoy disclosure
        let mut sd_cwt = sd_cwt_tagged.clone();
        let extra = Salted::Decoy(Decoy { salt: (Salt::empty(),) });
        sd_cwt.0.sd_unprotected.sd_claims.0.push(extra.into());
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure { expected, actual }))
            if expected == 8 && actual == 9
        ));

        // alter disclosure of the map element
        let mut sd_cwt = sd_cwt_tagged.clone();
        for d in &mut sd_cwt.0.sd_unprotected.sd_claims.0 {
            if let Salted::Claim(c) = d.to_value_mut().unwrap() {
                c.salt = Salt::empty()
            }
        }
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));

        // alter disclosure of the array element
        #[allow(clippy::redundant_clone)]
        let mut sd_cwt = sd_cwt_tagged.clone();
        for d in &mut sd_cwt.0.sd_unprotected.sd_claims.0 {
            if let Salted::Element(c) = d.to_value_mut().unwrap() {
                c.salt = Salt::empty()
            }
        }
        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        ));
    }

    #[test]
    fn should_fail_when_invalid_signature() {
        let mut csprng = ChaCha20Rng::from_entropy();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let holder = Ed25519Holder::<Value>::new(holder_signing_key.clone());

        let issuer_params = default_issuer_params(&holder_signing_key, None);
        let sd_cwt = issuer.issue_cwt(&mut csprng, issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let issuer_signing_key_bis = ed25519_dalek::SigningKey::generate(&mut csprng);

        assert!(matches!(
            holder.verify_sd_cwt(&sd_cwt, Default::default(), &issuer_signing_key_bis.verifying_key()),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::SignatureError(_)))
        ));
    }

    fn default_issuer_params(holder_signing_key: &ed25519_dalek::SigningKey, payload: Option<Value>) -> IssuerParams<Value> {
        IssuerParams::<Value> {
            protected_claims: None,
            unprotected_claims: None,
            payload,
            issuer: "issuer",
            subject: None,
            audience: None,
            expiry: None,
            with_not_before: false,
            with_issued_at: false,
            cti: None,
            cnonce: None,
            artificial_time: None,
            leeway: Default::default(),
            key_location: "",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
        }
    }
}
