pub mod error;
pub mod params;
mod walk;

use crate::{
    ShallowVerifierParams, VerifierParams,
    any_digest::AnyDigest,
    elapsed_since_epoch,
    signature_verifier::validate_signature,
    time::verify_time_claims,
    verifier::error::{SdCwtVerifierError, SdCwtVerifierResult},
};
use ahash::HashMap;
use ciborium::{Value, value::Integer};
use cose_key_confirmation::{KeyConfirmation, error::CoseKeyConfirmationError};
use esdicawt_spec::{
    CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, CwtAny, SdHashAlg, Select,
    issuance::SdInnerPayload,
    key_binding::KbtCwtTagged,
    reexports::coset::{CoseSign1, TaggedCborSerializable},
    verified::KbtCwtVerified,
};

pub trait Verifier {
    type Error: core::error::Error + Send + Sync;

    type HolderSignature: signature::SignatureEncoding;
    type HolderVerifier: signature::Verifier<Self::HolderSignature> + PartialEq + for<'a> TryFrom<&'a KeyConfirmation, Error = CoseKeyConfirmationError>;

    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type IssuerPayloadClaims: Select;
    type KbtPayloadClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtUnprotectedClaims: CustomClaims;

    #[cfg(not(any(feature = "ed25519", feature = "p256", feature = "p384")))]
    fn digest(&self, sd_alg: SdHashAlg, data: &[u8]) -> Result<Vec<u8>, SdCwtVerifierError<Self::Error>>;

    #[cfg(any(feature = "ed25519", feature = "p256", feature = "p384"))]
    fn digest(&self, sd_alg: SdHashAlg, data: &[u8]) -> Result<Vec<u8>, SdCwtVerifierError<Self::Error>> {
        Ok(match sd_alg {
            #[cfg(any(feature = "ed25519", feature = "p256"))]
            SdHashAlg::Sha256 => {
                use digest::Digest as _;
                sha2::Sha256::digest(data).to_vec()
            }
            #[cfg(feature = "p384")]
            SdHashAlg::Sha384 => {
                use digest::Digest as _;
                sha2::Sha384::digest(data).to_vec()
            }
            _ => unreachable!(),
        })
    }

    /// Only verify the signatures and the time claims without trying to rebuild the whole ClaimSet which
    /// is expensive by requiring a lot of hashes
    #[allow(clippy::type_complexity)]
    fn shallow_verify_sd_kbt(
        &self,
        raw_sd_kbt: &[u8],
        params: ShallowVerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key_set::CoseKeySet,
    ) -> Result<
        KbtCwtTagged<
            Self::IssuerPayloadClaims,
            AnyDigest,
            Self::KbtPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
        >,
        SdCwtVerifierError<Self::Error>,
    > {
        use signature::Verifier as _;

        let mut kbt = KbtCwtTagged::<
            Self::IssuerPayloadClaims,
            AnyDigest,
            Self::KbtPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
        >::from_cbor_bytes(raw_sd_kbt)?;

        let kbt_protected = kbt.0.protected.to_value_mut()?;
        let (sd_cwt, sd_cwt_bytes) = kbt_protected.kcwt.to_pair_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let key_confirmation = &sd_cwt_payload.cnf;

        let kbt_cose_sign1 = CoseSign1::from_tagged_slice(raw_sd_kbt)?;
        let sd_cwt_cose_sign1 = CoseSign1::from_tagged_slice(sd_cwt_bytes)?;

        let holder_confirmation_key: Self::HolderVerifier = key_confirmation.try_into()?;

        // First the Verifier must validate the SD-KBT as described in Section 7.2 of [RFC8392].
        // verifying signature
        kbt_cose_sign1.verify_signature(&[], |signature, raw_data| {
            let signature = Self::HolderSignature::try_from(signature).map_err(|_| SdCwtVerifierError::SignatureEncodingError)?;
            holder_confirmation_key.verify(raw_data, &signature).map_err(SdCwtVerifierError::from)
        })?;

        // verify confirmation key advertised in the KBT matches the expected one if supplied
        if let Some(hvk) = holder_verifier {
            let key_confirmation: Self::HolderVerifier = key_confirmation.try_into()?;
            if key_confirmation != *hvk {
                return Err(SdCwtVerifierError::UnexpectedKeyConfirmation);
            }
        }

        let kbt_payload = kbt.0.payload.to_value()?;

        // verify time claims of the SD-KBT
        let validation_time = params.artificial_time.map_or_else(|| elapsed_since_epoch().as_secs(), |t| t as u64);
        let (iat, exp, nbf) = (Some(kbt_payload.issued_at), kbt_payload.expiration, kbt_payload.not_before);
        verify_time_claims(validation_time, params.sd_kbt_leeway, iat, exp, nbf, params.sd_kbt_time_verification)?;

        // After validation, the SD-CWT MUST be extracted from the kcwt header, and validated as described in Section 7.2 of [RFC8392].
        // verify signature if a verifying key supplied
        validate_signature(&sd_cwt_cose_sign1, cks)?;

        // verify time claims of the SD-CWT
        let (iat, exp, nbf) = (sd_cwt_payload.inner.issued_at, sd_cwt_payload.inner.expiration, sd_cwt_payload.inner.not_before);
        verify_time_claims(validation_time, params.sd_cwt_leeway, iat, exp, nbf, params.sd_cwt_time_verification)?;

        Ok(kbt)
    }

    #[allow(clippy::type_complexity)]
    fn verify_sd_kbt(
        &self,
        raw_sd_kbt: &[u8],
        params: VerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key_set::CoseKeySet,
    ) -> Result<
        KbtCwtVerified<
            Self::IssuerPayloadClaims,
            Self::KbtPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
        >,
        SdCwtVerifierError<Self::Error>,
    > {
        let mut kbt = self.shallow_verify_sd_kbt(raw_sd_kbt, params.shallow(), holder_verifier, cks)?;

        let kbt_protected = kbt.0.protected.to_value_mut()?;
        let sd_cwt = kbt_protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;

        let kbt_payload = kbt.0.payload.try_into_value()?;

        // verify SD-KBT audience
        if let Some((expected, actual)) = params.expected_kbt_audience.zip(Some(&kbt_payload.audience))
            && actual != expected
        {
            return Err(SdCwtVerifierError::KbtAudienceMismatch {
                actual: actual.to_owned(),
                expected: expected.to_owned(),
            });
        }

        // verify SD-KBT cnonce
        if let Some((expected, actual)) = params.expected_cnonce.zip(kbt_payload.cnonce.as_deref())
            && actual != expected
        {
            return Err(SdCwtVerifierError::CnonceMismatch {
                actual: actual.to_owned(),
                expected: expected.to_owned(),
            });
        }

        // verify SD-CWT subject
        if let Some((actual, expected)) = sd_cwt_payload.inner.subject.as_ref().zip(params.expected_subject)
            && actual != expected
        {
            return Err(SdCwtVerifierError::SubMismatch {
                actual: actual.to_owned(),
                expected: expected.to_owned(),
            });
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
        if let Some((actual, expected)) = sd_cwt_payload.inner.audience.as_ref().zip(params.expected_audience)
            && actual != expected
        {
            return Err(SdCwtVerifierError::AudienceMismatch {
                actual: actual.to_owned(),
                expected: expected.to_owned(),
            });
        }

        let mut payload = sd_cwt_payload.to_cbor_value()?;
        let sd_alg = sd_cwt.0.protected.to_value_mut()?.sd_alg;

        // now verifying the disclosures
        if let Some(disclosures) = sd_cwt.0.disclosures_mut() {
            let disclosures_size = disclosures.len();

            // compute the hash of all disclosures
            let mut disclosures = disclosures
                .iter_mut()
                .map(|d| match d {
                    Ok(salted) => {
                        let bytes = salted.to_cbor_bytes()?;
                        let digest = self.digest(sd_alg, &bytes[..])?;
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

        // puncture the 'cnf' claim before deserialization
        if let Some(map) = payload.as_map_mut() {
            map.retain(|(k, _)| !matches!(k, Value::Integer(i) if *i == Integer::from(CWT_CLAIM_KEY_CONFIRMATION)));
        }

        // TODO: this might fail if `Self::IssuerPayloadClaims` does not support unknown claims (serde flatten etc..)
        let sd_cwt_payload = payload.deserialized::<SdInnerPayload<Self::IssuerPayloadClaims>>()?;
        let claimset = sd_cwt_payload.extra;

        let protected = kbt.0.protected.try_into_value()?.try_into()?;
        let unprotected = kbt.0.unprotected;

        Ok(KbtCwtVerified {
            protected,
            unprotected,
            payload: kbt_payload,
            claimset,
        })
    }
}

#[cfg(feature = "status")]
#[allow(dead_code)]
pub trait VerifierWithStatus: Verifier {
    #[allow(clippy::type_complexity)]
    async fn verify_sd_kbt_with_status<S: status_list::Status>(
        &mut self,
        raw_sd_kbt: &[u8],
        params: VerifierParams<'_>,
        status_list_params: crate::verifier::params::StatusListVerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key_set::CoseKeySet,
        // in case the issuer of the StatusList is different from the SD-CWT issuer
        status_list_cks: &cose_key_set::CoseKeySet,
    ) -> Result<
        KbtCwtVerified<
            Self::IssuerPayloadClaims,
            Self::KbtPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
        >,
        SdCwtVerifierError<Self::Error>,
    > {
        use crate::verifier::error::SdCwtStatusVerifierError;

        let mut kbt = self.shallow_verify_sd_kbt(raw_sd_kbt, params.shallow(), holder_verifier, cks)?;

        let kbt_protected = kbt.0.protected.to_value_mut()?;
        let sd_cwt = kbt_protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;

        // Read the StatusClaim from the SD-CWT to know where to fetch the Status from
        // Note: no StatusList for the SD-KBT as it is self-issued by a Holder
        let idx = sd_cwt_payload.inner.status.status_list.idx;
        let status_url = &sd_cwt_payload.inner.status.status_list.uri;
        // we then ask the Verifier to resolve the Status, so either:
        // - get it from a local in-memory cache
        // - get it from a database in case it was already set by another thread
        // - last, fetch it from Status issuer in case it's nowhere to be found
        let Some(raw_status_token) = self.get_status(status_url).await.map_err(SdCwtVerifierError::CustomError)? else {
            return Err(SdCwtStatusVerifierError::StatusNotFound(status_url.clone()).into());
        };

        let status_token = status_list::issuer::StatusListToken::<S>::from_cbor_bytes(raw_status_token)?;
        let status_token_sign1 = CoseSign1::from_tagged_slice(raw_status_token)?;

        // We validate the signature of the StatusListToken
        validate_signature(&status_token_sign1, status_list_cks).map_err(SdCwtStatusVerifierError::InvalidStatusTokenSignature)?;

        // verify time claims of the SD-CWT
        let validation_time = status_list_params.artificial_time.map_or_else(|| elapsed_since_epoch().as_secs(), |t| t as u64);
        let (iat, exp, nbf) = (Some(status_token.iat), status_token.exp, None);
        verify_time_claims(validation_time, status_list_params.leeway, iat, exp, nbf, status_list_params.time_verification)?;

        // now let's verify the status of the SD-KBT in the StatusList

        if idx > status_token.status_list.max_index() {
            return Err(SdCwtStatusVerifierError::IndexOutOfBounds(status_url.clone()).into());
        }

        let Some(status) = status_token.status_list.lst().get(idx) else {
            return Err(SdCwtStatusVerifierError::StatusIndexNotFound(idx, status_url.clone()).into());
        };

        if !status.is_valid() {
            return Err(SdCwtStatusVerifierError::StatusInvalid(status_url.clone()).into());
        }

        self.verify_sd_kbt(raw_sd_kbt, params, holder_verifier, cks)
    }

    fn get_status(&mut self, status_url: &url::Url) -> impl Future<Output = Result<Option<&[u8]>, Self::Error>>;
}

#[cfg(test)]
mod tests {
    use super::claims::CustomTokenClaims;
    use crate::verifier::error::SdCwtStatusVerifierError;
    use crate::{
        HolderParams, Issuer, IssuerParams, Presentation, SdCwtVerifierError, StatusParams, TimeArg, Verifier, VerifierParams,
        holder::Holder,
        signature_verifier::SignatureVerifierError,
        test_utils::{Ed25519Holder, Ed25519Issuer},
        verifier::{VerifierWithStatus, params::StatusListVerifierParams, test_utils::HybridVerifier},
    };
    use ciborium::{Value, cbor};
    use cose_key_set::CoseKeySet;
    use esdicawt_spec::{CustomClaims, CwtAny, NoClaims, Select, verified::KbtCwtVerified};
    use status_list::{OauthStatus, StatusList, issuer::StatusListIssuerParams};

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_valid_sd_cwt() {
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);
        let verified = verify(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);

        assert_eq!(verified.claimset.as_ref().unwrap().name.as_deref(), Some("Alice Smith"));
        assert_eq!(verified.sd_cwt().payload.subject, Some("https://example.com/u/alice.smith".into()));

        // should work without disclosures
        let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        verify(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_signature() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params.clone(), default_holder_params::<NoClaims>(), &holder_signing_key);
        let verifier = HybridVerifier::<Value, NoClaims>::default();

        // verifying Holder signature
        let holder_verifying_key_bis = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        assert!(matches!(
            verifier.verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_verifying_key_bis), &cks),
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
            Err(SdCwtVerifierError::IssuerSignatureValidationError(SignatureVerifierError::SignatureError(_)))
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

        let mut holder_params = default_holder_params::<NoClaims>();
        holder_params.audience = "kbt-aud-a";
        holder_params.cnonce.replace(b"kbt-cnonce-a");

        let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params.clone(), holder_params, &holder_signing_key);
        let verifier = HybridVerifier::<Value, NoClaims>::default();

        // by default do not validate anything
        verifier.verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_verifying_key), &cks).unwrap();

        // === verify SD-CWT subject
        // ok when same
        let params = VerifierParams {
            expected_subject: Some("sub-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_subject: Some("sub-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks),
            Err(SdCwtVerifierError::SubMismatch { expected, actual })
            if expected == "sub-b" && actual == "sub-a"
        ));

        // === verify SD-CWT issuer
        // ok when same
        let params = VerifierParams {
            expected_issuer: Some("iss-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_issuer: Some("iss-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks),
            Err(SdCwtVerifierError::IssuerMismatch { expected, actual })
            if expected == "iss-b" && actual == "iss-a"
        ));

        // === verify SD-CWT audience
        // ok when same
        let params = VerifierParams {
            expected_audience: Some("aud-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_audience: Some("aud-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks),
            Err(SdCwtVerifierError::AudienceMismatch { expected, actual })
            if expected == "aud-b" && actual == "aud-a"
        ));

        // === verify SD-KBT audience
        // ok when same
        let params = VerifierParams {
            expected_kbt_audience: Some("kbt-aud-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_kbt_audience: Some("kbt-aud-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks),
            Err(SdCwtVerifierError::KbtAudienceMismatch { expected, actual })
            if expected == "kbt-aud-b" && actual == "kbt-aud-a"
        ));

        // === verify SD-KBT cnonce
        // ok when same
        let params = VerifierParams {
            expected_cnonce: Some(b"kbt-cnonce-a"),
            ..Default::default()
        };
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks).unwrap();
        // fail when mismatch
        let params = VerifierParams {
            expected_cnonce: Some(b"kbt-cnonce-b"),
            ..Default::default()
        };
        assert!(matches!(
        verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_verifying_key), &cks),
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
            let holder_params = default_holder_params::<NoClaims>();
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

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_be_customizable() {
        #[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
        struct ExtraKbtClaims {
            pub foo: String,
        }
        let extra_kbt = ExtraKbtClaims { foo: "bar".into() };
        let payload = CustomTokenClaims { name: Some("Alice Smith".into()) };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);

        let mut holder_params = default_holder_params::<ExtraKbtClaims>();
        holder_params.extra_kbt_payload.replace(extra_kbt);

        let verified = verify(issuer_params, holder_params, &holder_signing_key);

        assert_eq!(verified.payload.extra.unwrap().foo, "bar".to_string());
    }

    #[tokio::test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    async fn should_verify_status() {
        use status_list::issuer::StatusListIssuer;

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);

        let status_uri = "https://example.com/statuslists/1".parse::<url::Url>().unwrap();
        issuer_params.status.uri = status_uri.clone();
        issuer_params.status.status_list_bit_index = 64;

        let (cks, sd_kbt, issuer_signing_key) = generate_sd_kbt(issuer_params.clone(), default_holder_params::<NoClaims>(), &holder_signing_key);
        let status_list_cks = &cks; // since status_list_token is issued by the SD-KBT issuer
        let mut verifier = HybridVerifier::<Value, NoClaims>::default();

        let mut status_list = StatusList::<OauthStatus>::with_capacity(1 << 10, None);

        let status_list_issuer_params = StatusListIssuerParams {
            uri: status_uri.clone(),
            artificial_time: None,
            expiry: None,
            ttl: None,
            key_id: None,
        };
        let status_issuer = Ed25519Issuer::<Value> {
            signer: issuer_signing_key,
            _marker: Default::default(),
        };
        let status_token = status_issuer.issue_status_list_token(&status_list, status_list_issuer_params.clone()).unwrap();

        // 1. nominal case, status_token is found, status at index is valid
        verifier.insert_status_in_cache(&status_uri, status_token.to_cbor_bytes().unwrap());

        let status_list_verifier_params = StatusListVerifierParams {
            leeway: Default::default(),
            time_verification: Default::default(),
            artificial_time: None,
        };
        let verifier_params = VerifierParams {
            expected_subject: None,
            expected_issuer: None,
            expected_audience: None,
            expected_kbt_audience: None,
            expected_cnonce: None,
            sd_cwt_leeway: Default::default(),
            sd_kbt_leeway: Default::default(),
            sd_cwt_time_verification: Default::default(),
            sd_kbt_time_verification: Default::default(),
            artificial_time: None,
        };
        verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap();

        // 2. cache is empty, status_token not found
        verifier.clear_cache();
        let err = verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::StatusNotFound(uri)) if uri == status_uri));

        // 3. status at index is not valid
        status_list.set(64, OauthStatus::Invalid);
        let status_token = status_issuer.issue_status_list_token(&status_list, status_list_issuer_params.clone()).unwrap();
        verifier.insert_status_in_cache(&status_uri, status_token.to_cbor_bytes().unwrap());
        let err = verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::StatusInvalid(uri)) if uri == status_uri));

        // 4. index is out of bounds
        let short_status_list = StatusList::<OauthStatus>::with_capacity(1 << 6, None);
        let short_status_token = status_issuer.issue_status_list_token(&short_status_list, status_list_issuer_params.clone()).unwrap();
        verifier.insert_status_in_cache(&status_uri, short_status_token.to_cbor_bytes().unwrap());
        let err = verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::IndexOutOfBounds(uri)) if uri == status_uri));

        // 5. ensure we don't have an off by one issue
        issuer_params.status.status_list_bit_index = 63;
        let (cks, sd_kbt, issuer_signing_key) = generate_sd_kbt(issuer_params.clone(), default_holder_params::<NoClaims>(), &holder_signing_key);
        let status_list_cks = &cks;
        let status_issuer = Ed25519Issuer::<Value> {
            signer: issuer_signing_key,
            _marker: Default::default(),
        };
        let status_token = status_issuer.issue_status_list_token(&status_list, status_list_issuer_params.clone()).unwrap();
        verifier.insert_status_in_cache(&status_uri, status_token.to_cbor_bytes().unwrap());

        verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap();

        // 6. should fail if status_token not signed by expected issuer
        let fake_status_token_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let fake_status_list_cks = CoseKeySet::new(&fake_status_token_signer.verifying_key()).unwrap();
        let err = verifier
            .verify_sd_kbt_with_status::<OauthStatus>(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, &fake_status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::InvalidStatusTokenSignature(_))));
    }

    fn verify<T: Select, U: CustomClaims>(issuer_params: IssuerParams<T>, holder_params: HolderParams<U>, holder_signing_key: &ed25519_dalek::SigningKey) -> KbtCwtVerified<T, U> {
        let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params.clone(), holder_params, holder_signing_key);
        let verifier = HybridVerifier::<T, U>::default();
        verifier
            .verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_signing_key.verifying_key()), &cks)
            .unwrap()
    }

    #[allow(clippy::type_complexity)]
    fn generate_sd_kbt<T: Select, U: CustomClaims>(
        issuer_params: IssuerParams<T>,
        holder_params: HolderParams<'_, U>,
        holder_signing_key: &ed25519_dalek::SigningKey,
    ) -> (CoseKeySet, Vec<u8>, ed25519_dalek::SigningKey) {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        let issuer = Ed25519Issuer::new(issuer_signing_key.clone());

        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params).unwrap().to_cbor_bytes().unwrap();
        let holder = Ed25519Holder::<Value, U>::new(holder_signing_key.clone());
        let cks = CoseKeySet::new(&issuer_signing_key).unwrap();
        let sd_cwt = holder.verify_sd_cwt(&sd_cwt, Default::default(), &cks).unwrap();
        let sd_kbt = holder.new_presentation(sd_cwt, holder_params).unwrap();
        (cks, sd_kbt.to_cbor_bytes().unwrap(), issuer_signing_key)
    }

    fn default_holder_params<'a, U: CustomClaims>() -> HolderParams<'a, U> {
        HolderParams {
            presentation: Presentation::Full,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: None,
            expiry: Some(TimeArg::Relative(core::time::Duration::from_secs(90 * 24 * 3600))),
            with_not_before: true,
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
            artificial_time: None,
            time_verification: Default::default(),
            leeway: Default::default(),
        }
    }

    fn default_issuer_params<T: Select>(payload: Option<T>, holder_signing_key: &ed25519_dalek::SigningKey) -> IssuerParams<'_, T> {
        IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload,
            subject: Some("https://example.com/u/alice.smith"),
            issuer: "https://example.com/i/acme.io",
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            expiry: None,
            with_not_before: true,
            with_issued_at: true,
            leeway: core::time::Duration::from_secs(1),
            key_location: "https://auth.acme.io/issuer.cwk",
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            artificial_time: None,
            status: StatusParams {
                status_list_bit_index: 0,
                uri: "https://example.com/statuslists/1".parse().unwrap(),
            },
        }
    }

    #[allow(dead_code, unused_variables, clippy::type_complexity)]
    fn should_be_object_safe(
        verifier: Box<
            dyn Verifier<
                    IssuerProtectedClaims = NoClaims,
                    IssuerUnprotectedClaims = NoClaims,
                    IssuerPayloadClaims = NoClaims,
                    KbtProtectedClaims = NoClaims,
                    KbtUnprotectedClaims = NoClaims,
                    KbtPayloadClaims = NoClaims,
                    Error = std::convert::Infallible,
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
    use url::Url;

    // TODO: turn generic again
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct HybridVerifier<DisclosedClaims: CustomClaims, KbtClaims: CustomClaims> {
        pub status_cache: HashMap<url::Url, Vec<u8>>,
        pub _marker: core::marker::PhantomData<(DisclosedClaims, KbtClaims)>,
    }

    impl<T: Select, U: CustomClaims> Default for HybridVerifier<T, U> {
        fn default() -> Self {
            Self {
                status_cache: Default::default(),
                _marker: Default::default(),
            }
        }
    }

    #[allow(unused)]
    impl<T: Select, U: CustomClaims> HybridVerifier<T, U> {
        pub(crate) fn clear_cache(&mut self) {
            self.status_cache.clear();
        }

        pub(crate) fn insert_status_in_cache(&mut self, status_url: &Url, status_token: Vec<u8>) {
            self.status_cache.entry(status_url.clone()).insert_entry(status_token);
        }
    }

    impl<T: Select, U: CustomClaims> Verifier for HybridVerifier<T, U> {
        type Error = std::convert::Infallible;
        type HolderSignature = ed25519_dalek::Signature;
        type HolderVerifier = ed25519_dalek::VerifyingKey;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = T;
        type KbtPayloadClaims = U;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;
    }

    impl<T: Select, U: CustomClaims> VerifierWithStatus for HybridVerifier<T, U> {
        async fn get_status(&mut self, status_url: &Url) -> Result<Option<&[u8]>, Self::Error> {
            Ok(self.status_cache.get(status_url).map(Vec::as_slice))
        }
    }
}
