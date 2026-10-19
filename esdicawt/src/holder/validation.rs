use crate::{
    spec::{
        CWT_CLAIM_SUBJECT, REDACTED_CLAIM_ELEMENT_TAG, SdCwtClaim,
        blinded_claims::{SaltedClaim, SaltedEntry},
        is_safe_tag,
        redacted_claims::RedactedClaimKeys,
    },
    time::TimeVerification,
};
use ciborium::Value;
use esdicawt_spec::blinded_claims::SaltedArrayHashing;

#[derive(Default, Debug, Clone)]
pub struct HolderValidationParams<'a> {
    pub expected_subject: Option<&'a str>,
    pub expected_issuer: Option<&'a str>,
    pub expected_audience: Option<&'a str>,
    pub expected_cnonce: Option<&'a [u8]>,
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    pub time_verification: TimeVerification,
    /// for testing
    pub artificial_time: Option<core::time::Duration>,
}

#[derive(Debug, thiserror::Error)]
pub enum SdCwtHolderValidationError<CustomError: Send + Sync> {
    #[error("Expected sub to be '{expected}' but was '{actual}'")]
    SubMismatch { expected: String, actual: String },
    #[error("The SD-CWT has no 'sub', neither in clear nor redacted")]
    MissingSubject,
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
    #[error(transparent)]
    CoseKeyError(#[from] cose_key::CoseKeyError),
    #[error("Signature encoding error")]
    SignatureEncodingError,
    #[error("{0}")]
    SpecError(&'static str),
    #[error("{0}")]
    ImplementationError(&'static str),
    #[error(transparent)]
    CustomError(CustomError),
}

/// Verifies that every Redacted Claim Hash has its disclosure. Returns the number of disclosures and the 'sub' claim,
/// either in clear or redacted at the root of the payload
pub fn validate_disclosures<E>(payload: &Value, disclosures: &SaltedArrayHashing<'_>) -> Result<(usize, Option<String>), SdCwtHolderValidationError<E>>
where
    E: core::error::Error + Send + Sync,
{
    let mut subject = None;
    let count = _validate(payload, disclosures, Some(&mut subject))?;
    Ok((count, subject))
}

/// `subject` is only looked for at the root of the payload
fn _validate<E>(payload: &Value, disclosures: &SaltedArrayHashing<'_>, mut subject: Option<&mut Option<String>>) -> Result<usize, SdCwtHolderValidationError<E>>
where
    E: core::error::Error + Send + Sync,
{
    let nested = |v: &Value| _validate(v, disclosures, None);
    // counts the disclosure and the ones nested in it
    let disclosed = |hash: &[u8]| {
        let disclosure = disclosures.get_unchecked(hash).ok_or(SdCwtHolderValidationError::DisclosureNotFound)?.as_ref();
        Ok::<_, SdCwtHolderValidationError<E>>((disclosure, 1 + disclosure.value().map(nested).transpose()?.unwrap_or_default()))
    };
    let is_subject = |label: &ciborium::value::Integer| *label == ciborium::value::Integer::from(CWT_CLAIM_SUBJECT);

    let mut count = 0;
    match payload {
        Value::Map(mapping) => {
            for (k, v) in mapping {
                match (k, v) {
                    (Value::Simple(RedactedClaimKeys::CWT_LABEL), rcks) => {
                        for rck in rcks.deserialized::<RedactedClaimKeys>()? {
                            let (disclosure, nb) = disclosed(&rck)?;
                            count += nb;
                            if let (
                                Some(subject),
                                SaltedEntry::Claim(SaltedClaim {
                                    name: SdCwtClaim::Int(CWT_CLAIM_SUBJECT),
                                    value: Value::Text(sub),
                                    ..
                                }),
                            ) = (subject.as_deref_mut(), disclosure)
                            {
                                *subject = Some(sub.clone());
                            }
                        }
                    }
                    (Value::Integer(label), Value::Text(sub)) if is_subject(label) => {
                        if let Some(subject) = subject.as_deref_mut() {
                            *subject = Some(sub.clone());
                        }
                    }
                    (_, v) => count += nested(v)?,
                }
            }
        }
        Value::Array(array) => {
            for element in array {
                count += match element {
                    Value::Tag(REDACTED_CLAIM_ELEMENT_TAG, rce) => {
                        disclosed(rce.as_bytes().ok_or(SdCwtHolderValidationError::SpecError("RedactedClaimElement should be a bstr"))?)?.1
                    }
                    e => nested(e)?,
                }
            }
        }
        Value::Tag(tag, inner) if is_safe_tag(*tag) => count += nested(inner)?,
        _ => {}
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use crate::{
        HolderValidationParams, IssuerParams, SdCwtHolderError, SdCwtHolderValidationError, StatusParams,
        holder::Holder,
        issuer::Issuer,
        signature_verifier::SignatureVerifierError,
        spec::{
            CwtAny, EsdicawtSpecError, NoClaims, Salt, SdCwtClaim,
            blinded_claims::{Decoy, SaltedElement, SaltedEntry},
            decoy,
            issuance::SdCwtIssued,
            sd,
        },
        test_utils::{Ed25519Holder, Ed25519Issuer},
    };
    use ciborium::{Value, cbor};
    use cose_key::keyset::CoseKeySet;
    use std::ops::DerefMut;

    #[test]
    fn should_verify_redacted_subject() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_verifying_key = CoseKeySet::builder().with(&issuer_signing_key.verifying_key()).unwrap().build();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        // a redacted 'sub' in a nested mapping is not the subject
        let payload = cbor!({ "nested" => { crate::spec::sd!(crate::spec::CWT_CLAIM_SUBJECT) => "sub-x" } }).unwrap();
        let mut issuer_params = default_issuer_params(&holder_signing_key, Some(payload));
        issuer_params.subject = crate::Subject::Redacted("sub-a");
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap().to_cbor_bytes().unwrap();

        let validation_params = |expected_subject| HolderValidationParams {
            expected_subject,
            ..Default::default()
        };
        holder.verify_sd_cwt(&sd_cwt, validation_params(None), &issuer_verifying_key).unwrap();
        holder.verify_sd_cwt(&sd_cwt, validation_params(Some("sub-a")), &issuer_verifying_key).unwrap();
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params(Some("sub-x")), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::SubMismatch { expected, actual })) if &expected == "sub-x" && &actual == "sub-a"
        );
    }

    #[test]
    fn should_fail_when_std_claims_mismatch() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_verifying_key = CoseKeySet::builder().with(&issuer_signing_key.verifying_key()).unwrap().build();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        let mut issuer_params = default_issuer_params(&holder_signing_key, None);
        issuer_params.issuer = "iss-a";
        issuer_params.subject = "sub-a".into();
        issuer_params.audience = Some("aud-a");
        issuer_params.cnonce = Some(b"cnonce-a");

        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let mut validation_params = HolderValidationParams {
            expected_subject: Some("sub-a"),
            expected_issuer: Some("iss-a"),
            expected_audience: Some("aud-a"),
            expected_cnonce: Some(b"cnonce-a"),
            leeway: Default::default(),
            time_verification: Default::default(),
            artificial_time: None,
        };

        // should work by default
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === sub mismatch ===
        validation_params.expected_subject.replace("sub-b");
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::SubMismatch { expected, actual })) if &expected == "sub-b" && &actual == "sub-a"
        );
        // works with right expectation
        validation_params.expected_subject.replace("sub-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === issuer mismatch ===
        validation_params.expected_issuer.replace("iss-b");
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::IssuerMismatch { expected, actual })) if &expected == "iss-b" && &actual == "iss-a"
        );
        // works with right expectation
        validation_params.expected_issuer.replace("iss-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === audience mismatch ===
        validation_params.expected_audience.replace("aud-b");
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::AudienceMismatch { expected, actual })) if &expected == "aud-b" && &actual == "aud-a"
        );
        // works with right expectation
        validation_params.expected_audience.replace("aud-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === cnonce mismatch ===
        validation_params.expected_cnonce.replace(b"cnonce-b");
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::CnonceMismatch { expected, actual })) if &expected == b"cnonce-b" && &actual == b"cnonce-a"
        );
        // works with right expectation
        validation_params.expected_cnonce.replace(b"cnonce-a");
        holder.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key).unwrap();

        // === verifying key mismatch
        let holder_bis = Ed25519Holder::<Value, NoClaims>::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));
        std::assert_matches!(
            holder_bis.verify_sd_cwt(&sd_cwt, validation_params.clone(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::VerifyingKeyMismatch))
        );
    }

    #[test]
    fn should_fail_when_disclosures_invalid() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_verifying_key = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        let payload = cbor!({
            sd!(42) => "a",
            sd!(43) => { sd!(44) => 4 },
            sd!(45) => [ sd!(46) ],
            sd!(47) => [sd!(Value::Array(vec![sd!(48)]))],
        })
        .unwrap();

        let issuer_params = default_issuer_params(&holder_signing_key, Some(payload));
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let sd_cwt_tagged = SdCwtIssued::<Value, sha2::Sha256>::from_cbor_bytes(&sd_cwt).unwrap();

        // remove disclosure of the map
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .disclosures_mut()
            .unwrap()
            .retain(|d| !matches!(d.to_value().unwrap(), c if c.name() == Some(&SdCwtClaim::Int(42))));
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );

        // remove disclosure of the inner map
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .disclosures_mut()
            .unwrap()
            .retain(|d| !matches!(d.to_value().unwrap(), c if c.name() == Some(&SdCwtClaim::Int(44))));
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );

        // remove disclosure of the array element
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .disclosures_mut()
            .unwrap()
            .retain(|d| !matches!(d.to_value().unwrap(), c if c.value() == Some(&cbor!(46).unwrap())));
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );

        // remove disclosure of the nested array element
        let mut sd_cwt = sd_cwt_tagged.clone();
        sd_cwt
            .disclosures_mut()
            .unwrap()
            .retain(|d| !matches!(d.to_value().unwrap(), c if c.value() == Some(&cbor!(48).unwrap())));
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );

        // adding extra disclosure
        let mut sd_cwt = sd_cwt_tagged.clone();
        let extra = SaltedEntry::Element(SaltedElement {
            value: cbor!("a").unwrap(),
            salt: Salt::empty(),
        });
        sd_cwt.disclosures_mut().unwrap().push(extra.into());
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure { expected, actual }))
            if expected == 8 && actual == 9
        );

        // adding extra decoy disclosure
        let mut sd_cwt = sd_cwt_tagged.clone();
        let extra = SaltedEntry::Decoy(Decoy { salt: Salt::empty() });
        sd_cwt.disclosures_mut().unwrap().push(extra.into());
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure { expected, actual }))
            if expected == 8 && actual == 9
        );

        // alter disclosure of the map element
        let mut sd_cwt = sd_cwt_tagged.clone();
        for d in sd_cwt.disclosures_mut().unwrap().deref_mut() {
            d.modify(|d| {
                if let SaltedEntry::Claim(c) = d {
                    c.salt = Salt::empty()
                }
            })
            .unwrap();
        }
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );

        // alter disclosure of the array element
        #[allow(clippy::redundant_clone)]
        let mut sd_cwt = sd_cwt_tagged.clone();
        for d in sd_cwt.disclosures_mut().unwrap().deref_mut() {
            d.modify(|d| {
                if let SaltedEntry::Element(c) = d {
                    c.salt = Salt::empty()
                }
            })
            .unwrap();
        }
        std::assert_matches!(
            holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
            Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
        );
    }

    #[test]
    fn should_fail_when_decoy_disclosure_missing() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_verifying_key = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        let payload = cbor!({ sd!(42) => "a", 43 => [decoy!(1)], decoy!(2) => null }).unwrap();
        let issuer_params = default_issuer_params(&holder_signing_key, Some(payload));
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap().to_cbor_bytes().unwrap();
        holder.verify_sd_cwt(&sd_cwt, Default::default(), &issuer_verifying_key).unwrap();

        let sd_cwt_tagged = SdCwtIssued::<Value, sha2::Sha256>::from_cbor_bytes(&sd_cwt).unwrap();
        let decoys = sd_cwt_tagged
            .disclosures()
            .unwrap()
            .iter()
            .enumerate()
            .filter_map(|(i, d)| matches!(d.unwrap(), SaltedEntry::Decoy(_)).then_some(i))
            .collect::<Vec<_>>();
        assert_eq!(decoys.len(), 2);

        // the holder must receive the disclosure of every decoy, in an array or in a mapping
        for decoy in decoys {
            let mut sd_cwt = sd_cwt_tagged.clone();
            sd_cwt.disclosures_mut().unwrap().remove(decoy);
            std::assert_matches!(
                holder.verify_sd_cwt(&sd_cwt.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key),
                Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::DisclosureNotFound))
            );
        }
    }

    #[test]
    fn duplicate_disclosure() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_verifying_key = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        let payload = cbor!({sd!(42) => "a"}).unwrap();

        let issuer_params = default_issuer_params(&holder_signing_key, Some(payload));
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap().to_cbor_bytes().unwrap();

        let mut sd_cwt_tagged = SdCwtIssued::<Value, sha2::Sha256>::from_cbor_bytes(&sd_cwt).unwrap();

        // duplicate a disclosure
        let disclosures = sd_cwt_tagged.disclosures_mut().unwrap();
        #[allow(clippy::indexing_slicing)]
        let duplicate = disclosures[0].clone();
        disclosures.push(duplicate);

        let err = holder
            .verify_sd_cwt(&sd_cwt_tagged.to_cbor_bytes().unwrap(), Default::default(), &issuer_verifying_key)
            .unwrap_err();
        std::assert_matches!(err, SdCwtHolderError::SpecError(EsdicawtSpecError::DuplicateDisclosure))
    }

    #[test]
    fn should_fail_when_invalid_signature() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::<Value>::new(issuer_signing_key);

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());

        let issuer_params = default_issuer_params(&holder_signing_key, None);
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();

        let issuer_signing_key_bis = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        std::assert_matches!(
            holder.verify_sd_cwt(
                &sd_cwt,
                Default::default(),
                &CoseKeySet::builder().with_signing_key(&issuer_signing_key_bis).unwrap().build()
            ),
            Err(SdCwtHolderError::IssuerSignatureValidationError(SignatureVerifierError::SignatureError(_)))
        );
    }

    fn default_issuer_params(holder_signing_key: &ed25519_dalek::SigningKey, payload: Option<Value>) -> IssuerParams<'_, Value> {
        IssuerParams::<Value> {
            protected_claims: None,
            unprotected_claims: None,
            payload,
            issuer: "issuer",
            subject: "subject".into(),
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
            status: StatusParams {
                status_list_bit_index: 0,
                uri: "https://example.com/statuslists/1".parse().unwrap(),
            },
        }
    }
}
