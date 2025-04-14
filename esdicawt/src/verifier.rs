pub mod error;
pub mod params;
mod walk;

use crate::{
    VerifierParams,
    signature_verifier::validate_signature,
    time::verify_time_claims,
    verifier::error::{SdCwtVerifierError, SdCwtVerifierResult},
};
use ciborium::{Value, value::Integer};
use cose_key_confirmation::{KeyConfirmation, error::CoseKeyConfirmationError};
use esdicawt_spec::{
    CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, CwtAny, SdHashAlg, Select,
    issuance::SdInnerPayload,
    key_binding::KbtCwtTagged,
    reexports::coset::{AsCborValue, CoseSign1, TaggedCborSerializable},
    verified::KbtCwtVerified,
};
use std::collections::HashMap;
use time::OffsetDateTime;

pub trait Verifier {
    type Error: core::error::Error + Send + Sync;

    type HolderSignature: signature::SignatureEncoding;
    type HolderVerifier: signature::Verifier<Self::HolderSignature> + PartialEq + for<'a> TryFrom<&'a KeyConfirmation, Error = CoseKeyConfirmationError>;

    type Hasher: digest::Digest + Clone;

    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type IssuerPayloadClaims: Select;
    type KbtUnprotectedClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtPayloadClaims: CustomClaims;

    fn digest(&self, sd_alg: SdHashAlg, data: &[u8]) -> Result<Vec<u8>, Self::Error>;

    #[allow(clippy::type_complexity)]
    fn verify_sd_kbt_from_bytes(
        &self,
        kbt_bytes: &[u8],
        params: VerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        keyset: &cose_key_set::CoseKeySet,
    ) -> Result<
        KbtCwtVerified<
            Self::IssuerPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
        >,
        SdCwtVerifierError<Self::Error>,
    > {
        let kbt_tagged = KbtCwtTagged::<
            Self::IssuerPayloadClaims,
            Self::Hasher,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
        >::from_cbor_bytes(kbt_bytes)?;
        self.verify_sd_kbt(&kbt_tagged, params, holder_verifier, keyset)
    }

    #[allow(clippy::type_complexity)]
    fn verify_sd_kbt(
        &self,
        kbt: &KbtCwtTagged<
            Self::IssuerPayloadClaims,
            Self::Hasher,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
        >,
        params: VerifierParams,
        holder_verifying_key: Option<&Self::HolderVerifier>,
        keyset: &cose_key_set::CoseKeySet,
    ) -> Result<
        KbtCwtVerified<
            Self::IssuerPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
        >,
        SdCwtVerifierError<Self::Error>,
    > {
        use signature::Verifier as _;

        // TODO: we're gonna mutate the token to serve the ClaimSet so we're lazy here and clone the
        // whole thing. We should at some point only clone the required parts
        let mut kbt = kbt.clone();

        let kbt_value = kbt.0.to_cbor_value()?;

        let kbt_protected = kbt.0.protected.to_value_mut()?;
        let (sd_cwt, sd_cwt_bytes) = kbt_protected.kcwt.to_pair_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let key_confirmation = &sd_cwt_payload.cnf;

        let holder_confirmation_key: Self::HolderVerifier = key_confirmation.try_into()?;

        let now = params.artificial_time.unwrap_or_else(|| OffsetDateTime::now_utc().unix_timestamp());

        // First the Verifier must validate the SD-KBT as described in Section 7.2 of [RFC8392].
        // verifying signature
        let cose_sign1_sd_kbt = CoseSign1::from_cbor_value(kbt_value)?;
        cose_sign1_sd_kbt.verify_signature(&[], |signature, raw_data| {
            let signature = Self::HolderSignature::try_from(signature).map_err(|_| SdCwtVerifierError::SignatureEncodingError)?;
            holder_confirmation_key.verify(raw_data, &signature).map_err(SdCwtVerifierError::from)
        })?;

        // verify confirmation key advertised in the KBT matches the expected one if supplied
        if let Some(hvk) = holder_verifying_key {
            let key_confirmation: Self::HolderVerifier = key_confirmation.try_into()?;
            if key_confirmation != *hvk {
                return Err(SdCwtVerifierError::UnexpectedKeyConfirmation);
            }
        }

        // verify time claims
        let kbt_payload = kbt.0.payload.to_value()?;

        // verify SD-KBT audience
        if let Some((expected, actual)) = params.expected_kbt_audience.zip(Some(&kbt_payload.audience)) {
            if actual != expected {
                return Err(SdCwtVerifierError::KbtAudienceMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-KBT cnonce
        if let Some((expected, actual)) = params.expected_cnonce.zip(kbt_payload.cnonce.as_deref()) {
            if actual != expected {
                return Err(SdCwtVerifierError::CnonceMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        verify_time_claims(now, params.leeway, Some(kbt_payload.issued_at), kbt_payload.expiration, kbt_payload.not_before)?;

        // TODO: verify revocation status w/ Status List

        // After validation, the SD-CWT MUST be extracted from the kcwt header, and validated as described in Section 7.2 of [RFC8392].
        // verify signature if a verifying key supplied
        let cose_sign1_sd_cwt = CoseSign1::from_tagged_slice(sd_cwt_bytes)?;
        validate_signature(&cose_sign1_sd_cwt, keyset)?;

        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;

        // verify SD-CWT subject
        if let Some((actual, expected)) = sd_cwt_payload.inner.subject.as_ref().zip(params.expected_subject) {
            if actual != expected {
                return Err(SdCwtVerifierError::SubMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-CWT issuer
        if let Some(expected) = params.expected_issuer {
            let actual = &sd_cwt_payload.inner.issuer;
            if actual != expected {
                return Err(SdCwtVerifierError::IssuerMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-CWT audience
        if let Some((actual, expected)) = sd_cwt_payload.inner.audience.as_ref().zip(params.expected_audience) {
            if actual != expected {
                return Err(SdCwtVerifierError::AudienceMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify time claims
        verify_time_claims(
            now,
            params.leeway,
            sd_cwt_payload.inner.issued_at,
            sd_cwt_payload.inner.expiration,
            sd_cwt_payload.inner.not_before,
        )?;

        // TODO: verify revocation status w/ Status List

        let mut payload = sd_cwt_payload.to_cbor_value()?;
        let sd_alg = sd_cwt.0.protected.to_value()?.sd_alg;

        // now verifying the disclosures
        if let Some(disclosures) = sd_cwt.0.disclosures_mut() {
            let disclosures_size = disclosures.len();

            // compute the hash of all disclosures
            let mut disclosures = disclosures
                .iter_mut()
                .map(|d| match d {
                    Ok(salted) => {
                        let bytes = salted.to_cbor_bytes()?;
                        let digest = self.digest(sd_alg, &bytes[..]).map_err(SdCwtVerifierError::CustomError)?;
                        SdCwtVerifierResult::Ok((digest, salted))
                    }
                    Err(e) => Err(e.into()),
                })
                .collect::<Result<HashMap<_, _>, _>>()?;

            if disclosures.len() != disclosures_size {
                return Err(SdCwtVerifierError::DisclosureHashCollision);
            }

            walk::walk_payload(&mut payload, &mut disclosures)?;
        }

        // removing the 'cnf' claim before deserialization
        if let Some(map) = payload.as_map_mut() {
            map.retain(|(k, _)| !matches!(k, Value::Integer(i) if *i == Integer::from(CWT_CLAIM_KEY_CONFIRMATION)));
        }

        // TODO: this might fail if `Self::DisclosedClaims` does not support unknown claims (serde flatten etc..)
        let sd_cwt_payload = payload.deserialized::<SdInnerPayload<Self::IssuerPayloadClaims>>()?;
        let claimset = sd_cwt_payload.extra;

        Ok(KbtCwtVerified {
            protected: kbt_protected.clone().try_into()?,
            unprotected: kbt.0.unprotected,
            payload: kbt.0.payload.try_into_value()?,
            claimset,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::claims::CustomTokenClaims;
    use crate::signature_verifier::SignatureVerifierError;
    use crate::{
        HolderParams, Issuer, IssuerParams, Presentation, SdCwtVerifierError, Verifier, VerifierParams,
        holder::Holder,
        test_utils::{Ed25519Holder, Ed25519Issuer},
        verifier::test_utils::HybridVerifier,
    };
    use ciborium::{Value, cbor};
    use cose_key_set::CoseKeySet;
    use esdicawt_spec::{CwtAny, NoClaims, Select, key_binding::KbtCwtTagged, verified::KbtCwtVerified};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_valid_sd_cwt() {
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);
        let verified = verify(issuer_params, default_holder_params(), &holder_signing_key);

        assert_eq!(verified.claimset.as_ref().unwrap().name.as_deref(), Some("Alice Smith"));
        assert_eq!(verified.sd_cwt().payload.subject, Some("https://example.com/u/alice.smith".into()));

        // should work without disclosures
        let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        verify(issuer_params, default_holder_params(), &holder_signing_key);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_signature() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        let (issuer_signing_key, sd_kbt) = generate(issuer_params.clone(), default_holder_params(), &holder_signing_key);
        let verifier = HybridVerifier { _marker: Default::default() };

        // verifying Holder signature
        let holder_verifying_key_bis = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        assert!(matches!(
            verifier.verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_verifying_key_bis), &CoseKeySet::new(&issuer_signing_key).unwrap()),
            Err(SdCwtVerifierError::UnexpectedKeyConfirmation)
        ));

        // verifying Issuer signature
        let issuer_verifying_key_bis = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        assert!(matches!(
            verifier.verify_sd_kbt(
                &sd_kbt,
                Default::default(),
                Some(&holder_signing_key.verifying_key()),
                &CoseKeySet::new(&issuer_verifying_key_bis).unwrap()
            ),
            Err(SdCwtVerifierError::SignatureValidationError(SignatureVerifierError::NoSigner))
        ));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_std_claims() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder_verifying_key = holder_signing_key.verifying_key();

        let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        issuer_params.issuer = "iss-a";
        issuer_params.subject.replace("sub-a");
        issuer_params.audience.replace("aud-a");

        let mut holder_params = default_holder_params();
        holder_params.audience = "kbt-aud-a";
        holder_params.cnonce.replace(b"kbt-cnonce-a");

        let (issuer_signing_key, sd_kbt) = generate(issuer_params.clone(), holder_params, &holder_signing_key);
        let verifier = HybridVerifier { _marker: Default::default() };

        // by default do not validate anything
        let issuer_verifying_key = CoseKeySet::new(&issuer_signing_key).unwrap();
        verifier
            .verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_verifying_key), &issuer_verifying_key)
            .unwrap();

        // === verify SD-CWT subject
        // ok when same
        let params = VerifierParams {
            expected_subject: Some("sub-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_subject: Some("sub-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key),
            Err(SdCwtVerifierError::SubMismatch { expected, actual })
            if expected == "sub-b" && actual == "sub-a"
        ));

        // === verify SD-CWT issuer
        // ok when same
        let params = VerifierParams {
            expected_issuer: Some("iss-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_issuer: Some("iss-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key),
            Err(SdCwtVerifierError::IssuerMismatch { expected, actual })
            if expected == "iss-b" && actual == "iss-a"
        ));

        // === verify SD-CWT audience
        // ok when same
        let params = VerifierParams {
            expected_audience: Some("aud-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_audience: Some("aud-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key),
            Err(SdCwtVerifierError::AudienceMismatch { expected, actual })
            if expected == "aud-b" && actual == "aud-a"
        ));

        // === verify SD-KBT audience
        // ok when same
        let params = VerifierParams {
            expected_kbt_audience: Some("kbt-aud-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_kbt_audience: Some("kbt-aud-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key),
            Err(SdCwtVerifierError::KbtAudienceMismatch { expected, actual })
            if expected == "kbt-aud-b" && actual == "kbt-aud-a"
        ));

        // === verify SD-KBT cnonce
        // ok when same
        let params = VerifierParams {
            expected_cnonce: Some(b"kbt-cnonce-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_cnonce: Some(b"kbt-cnonce-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &issuer_verifying_key),
            Err(SdCwtVerifierError::CnonceMismatch { expected, actual })
            if expected == b"kbt-cnonce-b" && actual == b"kbt-cnonce-a"
        ));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_complex() {
        let verifying = |value: Result<Value, ciborium::value::Error>| {
            let value = value.unwrap();
            let payload = cbor!({ "___claim" => value }).unwrap();
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);
            let holder_params = default_holder_params();
            let verified = verify(issuer_params, holder_params, &holder_signing_key);

            let claimset = verified.claimset.unwrap().into_map().unwrap();
            let (_, claim) = claimset.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == "___claim")).unwrap();
            assert_eq!(claim, &value);
        };

        // simple string
        verifying(cbor!("a"));

        // nested mapping
        verifying(cbor!({ "a" => "b" }));

        // simple array
        verifying(cbor!([0, 1]));

        // nested array
        verifying(cbor!([[0, 1]]));

        // mapping in array
        verifying(cbor!([{ "a" => "b"} ]));

        // array in mapping
        verifying(cbor!({ "a" => [0, 1] }));
    }

    fn verify<T: Select>(issuer_params: IssuerParams<T>, holder_params: HolderParams, holder_signing_key: &ed25519_dalek::SigningKey) -> KbtCwtVerified<T> {
        let (issuer_signing_key, sd_kbt) = generate(issuer_params.clone(), holder_params, holder_signing_key);
        let verifier = HybridVerifier::<T> { _marker: Default::default() };
        verifier
            .verify_sd_kbt(
                &sd_kbt,
                Default::default(),
                Some(&holder_signing_key.verifying_key()),
                &CoseKeySet::new(&issuer_signing_key).unwrap(),
            )
            .unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn generate<T: Select>(
        issuer_params: IssuerParams<T>,
        holder_params: HolderParams,
        holder_signing_key: &ed25519_dalek::SigningKey,
    ) -> (ed25519_dalek::SigningKey, KbtCwtTagged<T, sha2::Sha256>) {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let issuer = Ed25519Issuer::new(issuer_signing_key.clone());

        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap().to_cbor_bytes().unwrap();
        let holder = Ed25519Holder::new(holder_signing_key.clone());
        let sd_cwt = holder.verify_sd_cwt(&sd_cwt, Default::default(), &CoseKeySet::new(&issuer_signing_key).unwrap()).unwrap();
        let sd_kbt = holder.new_presentation(sd_cwt, holder_params).unwrap();
        (issuer_signing_key, sd_kbt)
    }

    fn default_holder_params<'a>() -> HolderParams<'a> {
        HolderParams {
            presentation: Presentation::Full,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: None,
            expiry: Some(core::time::Duration::from_secs(90 * 24 * 3600)),
            with_not_before: true,
            leeway: core::time::Duration::from_secs(3600),
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
            artificial_time: None,
        }
    }

    fn default_issuer_params<T: Select>(payload: Option<T>, holder_signing_key: &ed25519_dalek::SigningKey) -> IssuerParams<T> {
        IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload,
            subject: Some("https://example.com/u/alice.smith"),
            issuer: "https://example.com/i/acme.io",
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            expiry: Some(core::time::Duration::from_secs(90)),
            with_not_before: true,
            with_issued_at: true,
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.acme.io/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            artificial_time: None,
        }
    }

    #[allow(dead_code, unused_variables, clippy::type_complexity)]
    fn should_be_object_safe(
        holder: Box<
            dyn Verifier<
                    IssuerProtectedClaims = NoClaims,
                    IssuerPayloadClaims = NoClaims,
                    IssuerUnprotectedClaims = NoClaims,
                    KbtProtectedClaims = NoClaims,
                    KbtUnprotectedClaims = NoClaims,
                    KbtPayloadClaims = NoClaims,
                    Error = std::convert::Infallible,
                    Hasher = sha2::Sha256,
                    HolderSignature = ed25519_dalek::Signature,
                    HolderVerifier = ed25519_dalek::VerifyingKey,
                >,
        >,
    ) {
    }
}

#[cfg(test)]
pub mod claims {
    use ciborium::Value;
    use esdicawt_spec::{Select, sd};

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub(super) struct CustomTokenClaims {
        pub name: Option<String>,
    }

    impl Select for CustomTokenClaims {
        fn select(self) -> Result<Value, ciborium::value::Error> {
            let mut map = Vec::with_capacity(1);
            if let Some(name) = self.name {
                map.push((sd!("name"), Value::Text(name)));
            }
            Ok(Value::Map(map))
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use esdicawt_spec::NoClaims;

    // TODO: turn generic again
    #[derive(Debug, Clone, Default)]
    pub struct HybridVerifier<DisclosedClaims: CustomClaims> {
        pub _marker: core::marker::PhantomData<DisclosedClaims>,
    }

    impl<T: Select> Verifier for HybridVerifier<T> {
        type Error = std::convert::Infallible;
        type HolderSignature = ed25519_dalek::Signature;
        type HolderVerifier = ed25519_dalek::VerifyingKey;
        type Hasher = sha2::Sha256;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = T;
        type KbtUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;

        fn digest(&self, sd_alg: SdHashAlg, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
            use digest::Digest as _;
            Ok(match sd_alg {
                SdHashAlg::Sha256 => sha2::Sha256::digest(data).to_vec(),
                _ => unreachable!(),
            })
        }
    }
}
