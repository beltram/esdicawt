pub mod error;
pub mod params;
pub mod walk;

use crate::{
    CwtStdLabel, ShallowVerifierParams, VerifierParams,
    any_digest::AnyDigest,
    elapsed_since_epoch,
    spec::{CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, CwtAny, SdHashAlg, Select, issuance::SdInnerPayload, key_binding::KbtCwtTagged, reexports::coset, verified::KbtCwtVerified},
    time::verify_time_claims,
    verifier::error::SdCwtVerifierError,
};
use ciborium::{Value, value::Integer};
use cose_key::confirmation::{CoseKeyConfirmationError, KeyConfirmation};
use coset::{CoseSign1, TaggedCborSerializable};
use std::rc::Rc;

pub trait Verifier {
    type Error: core::error::Error + Send + Sync;

    type HolderSignature: signature::SignatureEncoding;

    type HolderVerifier: signature::Verifier<Self::HolderSignature> + AsRef<[u8]> + PartialEq + for<'a> TryFrom<&'a KeyConfirmation, Error = CoseKeyConfirmationError>;

    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type IssuerPayloadClaims: Select;
    type KbtPayloadClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtUnprotectedClaims: CustomClaims;

    #[cfg(any(feature = "ed25519", feature = "p256", feature = "p384"))]
    fn digest(&self, sd_alg: SdHashAlg) -> Rc<dyn digest::DynDigest> {
        match sd_alg {
            #[cfg(any(feature = "ed25519", feature = "p256"))]
            SdHashAlg::Sha256 => Rc::new(sha2::Sha256::default()),
            #[cfg(feature = "p384")]
            SdHashAlg::Sha384 => Rc::new(sha2::Sha384::default()),
            _ => unreachable!(),
        }
    }

    #[cfg(not(any(feature = "ed25519", feature = "p256", feature = "p384")))]
    fn digest(&self, sd_alg: SdHashAlg) -> Rc<dyn digest::DynDigest>;

    /// Only verify the signatures and the time claims without trying to rebuild the whole ClaimSet which
    /// is expensive by requiring a lot of hashes
    #[allow(clippy::type_complexity)]
    fn shallow_verify_sd_kbt(
        &self,
        raw_sd_kbt: &[u8],
        params: ShallowVerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key::keyset::CoseKeySet,
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
        let (kbt, _) = __shallow_verify_sd_kbt(raw_sd_kbt, params, holder_verifier, cks)?;
        Ok(kbt)
    }

    #[allow(clippy::type_complexity)]
    fn verify_sd_kbt(
        &self,
        raw_sd_kbt: &[u8],
        params: VerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key::keyset::CoseKeySet,
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
        let (mut kbt, mut generic_sd_cwt_payload) = __shallow_verify_sd_kbt(raw_sd_kbt, params.shallow(), holder_verifier, cks)?;
        let generic_sd_cwt_payload_map = generic_sd_cwt_payload.as_map().ok_or(SdCwtVerifierError::InvalidSdCwt)?;

        let kbt_protected = kbt.0.protected.to_value_mut()?;

        let (mut sub, mut iss, mut aud) = (None, None, None);

        for (k, value) in generic_sd_cwt_payload_map {
            match (k.as_integer(), value) {
                (Some(i), Value::Text(v)) if i == CwtStdLabel::Subject => {
                    sub.replace(v);
                }
                (Some(i), Value::Text(v)) if i == CwtStdLabel::Issuer => {
                    iss.replace(v);
                }
                (Some(i), Value::Text(v)) if i == CwtStdLabel::Audience => {
                    aud.replace(v);
                }
                _ => {}
            }
        }

        let kbt_payload = kbt.0.payload.try_into_value()?;

        // verify SD-KBT audience
        if let Some(expected) = params.expected_kbt_audience {
            let actual = &kbt_payload.audience;
            if actual != expected {
                return Err(SdCwtVerifierError::KbtAudienceMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-KBT cnonce
        if let Some(expected) = params.expected_cnonce {
            let actual = kbt_payload.cnonce.as_ref().map(|bb| bb.to_vec()).unwrap_or_default();
            if actual != expected {
                return Err(SdCwtVerifierError::CnonceMismatch {
                    actual,
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-CWT subject
        if let Some(expected) = params.expected_subject {
            if let Some(actual) = sub {
                if actual != expected {
                    return Err(SdCwtVerifierError::SubMismatch {
                        actual: actual.to_owned(),
                        expected: expected.to_owned(),
                    });
                }
            } else {
                return Err(SdCwtVerifierError::SubMismatch {
                    actual: Default::default(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-CWT issuer
        if let Some(expected) = params.expected_issuer {
            let actual = iss.ok_or(SdCwtVerifierError::MalformedSdCwt("Missing issuer"))?;
            if actual != expected {
                return Err(SdCwtVerifierError::IssuerMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                });
            }
        }

        // verify SD-CWT audience
        if let Some(expected) = params.expected_audience {
            if let Some(actual) = aud {
                if actual != expected {
                    return Err(SdCwtVerifierError::AudienceMismatch {
                        actual: actual.to_owned(),
                        expected: expected.to_owned(),
                    });
                }
            } else {
                return Err(SdCwtVerifierError::AudienceMismatch {
                    actual: Default::default(),
                    expected: expected.to_owned(),
                });
            }
        }

        let sd_alg = kbt_protected.kcwt.protected.to_value_mut()?.sd_alg;

        // now verifying the disclosures
        if let Some(disclosures) = kbt_protected.kcwt.disclosures_mut() {
            let disclosures_size = disclosures.len();
            // compute the hash of all disclosures
            let mut disclosures = disclosures.to_verify()?;

            // FIXME: this does actually look for collisions
            if disclosures.len() != disclosures_size {
                return Err(SdCwtVerifierError::DisclosureHashCollision);
            }

            walk::walk_payload(self.digest(sd_alg), &mut generic_sd_cwt_payload, &mut disclosures)?;

            // disclosures not found in the SD-CWT payload => invalid
            let orphan_disclosures = disclosures;
            if !orphan_disclosures.is_empty() {
                return Err(SdCwtVerifierError::OrphanDisclosure);
            }
        }

        // puncture the 'cnf' claim before deserialization
        if let Some(map) = generic_sd_cwt_payload.as_map_mut() {
            map.retain(|(k, _)| !matches!(k, Value::Integer(i) if *i == Integer::from(CWT_CLAIM_KEY_CONFIRMATION)));
        }

        // TODO: this might fail if `Self::IssuerPayloadClaims` does not support unknown claims (serde flatten etc..)
        let sd_cwt_payload = generic_sd_cwt_payload.deserialized::<SdInnerPayload<Self::IssuerPayloadClaims>>()?;
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

#[allow(clippy::type_complexity)]
fn __shallow_verify_sd_kbt<
    Error: core::error::Error + Send + Sync,
    HolderSignature: signature::SignatureEncoding,
    HolderVerifier: signature::Verifier<HolderSignature> + AsRef<[u8]> + PartialEq + for<'a> TryFrom<&'a KeyConfirmation, Error = CoseKeyConfirmationError>,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: Select,
    KbtPayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
>(
    raw_sd_kbt: &[u8],
    params: ShallowVerifierParams,
    // not mandatory in case the verifier does not have access to it
    holder_verifier: Option<&HolderVerifier>,
    cks: &cose_key::keyset::CoseKeySet,
) -> Result<
    (
        KbtCwtTagged<IssuerPayloadClaims, AnyDigest, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>,
        Value,
    ),
    SdCwtVerifierError<Error>,
> {
    let mut kbt = KbtCwtTagged::<
        IssuerPayloadClaims,
        AnyDigest,
        KbtPayloadClaims,
        IssuerProtectedClaims,
        IssuerUnprotectedClaims,
        KbtProtectedClaims,
        KbtUnprotectedClaims,
    >::from_cbor_bytes(raw_sd_kbt)?;

    let generic_sd_cwt = kbt.0.generic_sd_cwt()?;
    let kbt_protected = kbt.0.protected.to_value_mut()?;

    let generic_sd_cwt_payload = generic_sd_cwt.payload.upcast_value()?;
    let generic_sd_cwt_payload_map = generic_sd_cwt_payload.as_map().ok_or(SdCwtVerifierError::InvalidSdCwt)?;
    let sd_cwt_bytes = kbt_protected.kcwt.to_cbor_bytes()?;

    let mut key_confirmation = None;
    let (mut iat, mut exp, mut nbf) = (None, None, None);

    for (k, value) in generic_sd_cwt_payload_map {
        match (k.as_integer(), value) {
            (Some(i), v) if i == CwtStdLabel::KeyConfirmation => {
                key_confirmation.replace(v);
            }
            (Some(i), Value::Integer(v)) if i == CwtStdLabel::IssuedAt => {
                iat.replace(i128::from(*v) as i64);
            }
            (Some(i), Value::Integer(v)) if i == CwtStdLabel::ExpiresAt => {
                exp.replace(i128::from(*v) as i64);
            }
            (Some(i), Value::Integer(v)) if i == CwtStdLabel::NotBefore => {
                nbf.replace(i128::from(*v) as i64);
            }
            _ => {}
        }
    }

    // verify time claims of the SD-CWT
    let validation_time = params.artificial_time.map_or_else(|| elapsed_since_epoch().as_secs(), |t| t as u64);
    verify_time_claims(validation_time, params.sd_cwt_leeway, iat, exp, nbf, params.sd_cwt_time_verification)?;

    let key_confirmation = &key_confirmation
        .ok_or(SdCwtVerifierError::<Error>::MalformedSdCwt("Missing KeyConfirmation"))?
        .deserialized::<KeyConfirmation>()?;

    let kbt_cose_sign1 = CoseSign1::from_tagged_slice(raw_sd_kbt)?;
    let sd_cwt_cose_sign1 = CoseSign1::from_tagged_slice(&sd_cwt_bytes)?;

    // First the Verifier must validate the SD-KBT as described in Section 7.2 of [RFC8392].
    // verifying signature
    let holder_verifier_key: HolderVerifier = key_confirmation.try_into()?;

    // verify confirmation key advertised in the KBT matches the expected one if supplied
    if let Some(hvk) = holder_verifier {
        let key_confirmation: HolderVerifier = key_confirmation.try_into()?;
        if key_confirmation != *hvk {
            return Err(SdCwtVerifierError::UnexpectedKeyConfirmation);
        }
    }

    const ED25519_DALEK_SIGNATURE_LENGTH: usize = 64;

    if cfg!(feature = "ed25519")
        && let KeyConfirmation::CoseKey(key) = key_confirmation
        && key.alg() == Some(coset::iana::Algorithm::EdDSA)
        && key.crv() == Some(coset::iana::EllipticCurve::Ed25519)
        && sd_cwt_cose_sign1.protected.header.alg == Some(coset::Algorithm::Assigned(coset::iana::Algorithm::EdDSA))
        // only way to differentiate ed25519 from ed448 since we do not have crv
        && sd_cwt_cose_sign1.signature.len() == ED25519_DALEK_SIGNATURE_LENGTH
    {
        #[cfg(feature = "ed25519")]
        {
            // just for the feature scoped imports
            let kbt_tbs = &kbt_cose_sign1.tbs_data(&[]);
            let kbt_signature = ed25519_dalek::Signature::from_slice(&kbt_cose_sign1.signature)?;

            let sd_cwt_tbs = &sd_cwt_cose_sign1.tbs_data(&[]);
            let sd_cwt_signature = ed25519_dalek::Signature::from_slice(&sd_cwt_cose_sign1.signature)?;

            let holder_verifying_key = holder_verifier_key.as_ref().try_into().map_err(crate::signature_verifier::SignatureVerifierError::from)?;
            let holder_verifier_key = ed25519_dalek::VerifyingKey::from_bytes(holder_verifying_key).map_err(crate::signature_verifier::SignatureVerifierError::from)?;

            let mut verified = false;
            let mut first_err = None;
            for key in cks.find_keys(&coset::iana::Algorithm::EdDSA) {
                if key.crv() == Some(coset::iana::EllipticCurve::Ed25519) {
                    let sd_cwt_verifier = ed25519_dalek::VerifyingKey::try_from(key).map_err(crate::signature_verifier::SignatureVerifierError::from)?;
                    let verification = ed25519_dalek::verify_batch(&[kbt_tbs, sd_cwt_tbs], &[kbt_signature, sd_cwt_signature], &[holder_verifier_key, sd_cwt_verifier]);
                    match verification {
                        Ok(_) => {
                            verified = true;
                            break;
                        }
                        Err(e) => {
                            if first_err.is_none() {
                                first_err.replace(e);
                            }
                        }
                    }
                }
            }
            if !verified {
                return first_err.map_or_else(
                    || Err(crate::signature_verifier::SignatureVerifierError::NoSigner.into()),
                    |e| Err(SdCwtVerifierError::SignatureError(e)),
                );
            }
        }
    } else {
        kbt_cose_sign1.verify_signature(&[], |signature, raw_data| {
            let signature = HolderSignature::try_from(signature).map_err(|_| SdCwtVerifierError::SignatureEncodingError)?;
            holder_verifier_key.verify(raw_data, &signature).map_err(SdCwtVerifierError::from)
        })?;
        // After validation, the SD-CWT MUST be extracted from the kcwt header, and validated as described in Section 7.2 of [RFC8392].
        // verify signature if a verifying key supplied
        crate::signature_verifier::validate_cose_sign1_signature(&sd_cwt_cose_sign1, cks)?;
    }

    let kbt_payload = kbt.0.payload.to_value()?;

    // verify time claims of the SD-KBT
    let (iat, exp, nbf) = (Some(kbt_payload.issued_at), kbt_payload.expiration, kbt_payload.not_before);
    verify_time_claims(validation_time, params.sd_kbt_leeway, iat, exp, nbf, params.sd_kbt_time_verification)?;

    Ok((kbt, generic_sd_cwt_payload))
}

#[cfg(feature = "status")]
#[allow(dead_code)]
pub trait VerifierWithStatus: Verifier {
    type Status: status_list::Status;

    #[allow(clippy::type_complexity, async_fn_in_trait)]
    async fn verify_sd_kbt_with_status(
        &self,
        raw_sd_kbt: &[u8],
        params: VerifierParams<'_>,
        status_list_params: crate::verifier::params::StatusListVerifierParams,
        // not mandatory in case the verifier does not have access to it
        holder_verifier: Option<&Self::HolderVerifier>,
        cks: &cose_key::keyset::CoseKeySet,
        // in case the issuer of the StatusList is different from the SD-CWT issuer
        status_list_cks: &cose_key::keyset::CoseKeySet,
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
        let sd_cwt_payload = kbt_protected.kcwt.payload.to_value_mut()?;

        // Read the StatusClaim from the SD-CWT to know where to fetch the Status from
        // Note: no StatusList for the SD-KBT as it is self-issued by a Holder
        let idx = sd_cwt_payload.inner.status.status_list.idx;
        let status_url = &sd_cwt_payload.inner.status.status_list.uri;
        // we then ask the Verifier to resolve the Status, so either:
        // - get it from a local in-memory cache
        // - get it from a database in case it was already set by another thread
        // - last, fetch it from Status issuer in case it's nowhere to be found
        if let Some(status_token) = self.get_status_token(status_url.as_str(), status_list_cks).await? {
            // verify time claims of the StatusListToken
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

            use status_list::Status as _;
            if !status.is_valid() {
                return Err(SdCwtStatusVerifierError::StatusInvalid(status_url.clone()).into());
            }
        } else if status_list_params.ignore_status_list_not_found {
            // do nothing, just continue
        } else {
            return Err(SdCwtStatusVerifierError::StatusNotFound(status_url.clone()).into());
        };

        self.verify_sd_kbt(raw_sd_kbt, params, holder_verifier, cks)
    }

    #[allow(clippy::type_complexity)]
    fn get_status_token(
        &self,
        status_url: &str,
        status_list_cks: &cose_key::keyset::CoseKeySet,
    ) -> impl Future<Output = Result<Option<std::sync::Arc<VerifiedStatusListToken<Self::Status>>>, SdCwtVerifierError<Self::Error>>> + Send;

    fn verify_status_token(
        &self,
        raw_status_token: &[u8],
        status_list_cks: &cose_key::keyset::CoseKeySet,
    ) -> Result<VerifiedStatusListToken<Self::Status>, SdCwtVerifierError<Self::Error>> {
        let status_token = status_list::issuer::StatusListToken::from_cbor_bytes(raw_status_token)?;
        let status_token_sign1 = CoseSign1::from_tagged_slice(raw_status_token)?;

        // We validate the signature of the StatusListToken
        crate::signature_verifier::validate_cose_sign1_signature(&status_token_sign1, status_list_cks)
            .map_err(crate::verifier::error::SdCwtStatusVerifierError::InvalidStatusTokenSignature)?;
        Ok(VerifiedStatusListToken(status_token))
    }
}

#[cfg(feature = "status")]
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct VerifiedStatusListToken<S: status_list::Status>(status_list::issuer::StatusListToken<S>);

#[cfg(feature = "status")]
impl<S: status_list::Status> std::ops::Deref for VerifiedStatusListToken<S> {
    type Target = status_list::issuer::StatusListToken<S>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::claims::{CustomTokenClaims, Stuff};
    use crate::{
        CwtTimeError, HolderParams, Issuer, IssuerParams, Presentation, SdCwtVerifierError, StatusParams, TimeArg, Verifier, VerifierParams, elapsed_since_epoch,
        holder::Holder,
        spec::{CustomClaims, CwtAny, NoClaims, Select, sd, verified::KbtCwtVerified},
        test_utils::{Ed25519Holder, Ed25519Issuer},
        verifier::{VerifierWithStatus, error::SdCwtStatusVerifierError, test_utils::HybridVerifier},
    };
    use ciborium::{Value, cbor};
    use cose_key::keyset::CoseKeySet;
    use status_list::{OauthStatus, StatusList, issuer::StatusListIssuerParams};
    use std::convert::Infallible;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_verify_valid_sd_cwt() {
        let payload = CustomTokenClaims {
            name: Some("Alice Smith".into()),
            stuffs: vec![Stuff { foo: "bar".into() }],
        };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);
        let verified = verify(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key).unwrap();

        let claimset = verified.claimset.clone().unwrap();
        assert_eq!(claimset.name.as_deref(), Some("Alice Smith"));
        assert_eq!(claimset.stuffs, vec![Stuff { foo: "bar".into() }]);
        assert_eq!(verified.sd_cwt().payload.subject, Some("https://example.com/u/alice.smith".into()));

        // should work without disclosures
        let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
        verify(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key).unwrap();
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
                &CoseKeySet::builder().with(&issuer_verifying_key_bis).unwrap().build()
            ),
            Err(SdCwtVerifierError::SignatureError(_))
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
            let verified = verify(issuer_params, holder_params, &holder_signing_key).unwrap();

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
        let payload = CustomTokenClaims {
            name: Some("Alice Smith".into()),
            stuffs: Default::default(),
        };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);

        let mut holder_params = default_holder_params::<ExtraKbtClaims>();
        holder_params.extra_kbt_payload.replace(extra_kbt);

        let verified = verify(issuer_params, holder_params, &holder_signing_key).unwrap();

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
        verifier.insert_status_in_cache(&status_uri, status_token.to_cbor_bytes().unwrap(), &cks);

        let status_list_verifier_params = Default::default();
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
            .verify_sd_kbt_with_status(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap();

        // 2. cache is empty, status_token not found
        verifier.clear_cache();
        let err = verifier
            .verify_sd_kbt_with_status(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::StatusNotFound(uri)) if uri == status_uri));

        // 3. status at index is not valid
        status_list.set(64, OauthStatus::Invalid);
        let status_token_invalid_index = status_issuer.issue_status_list_token(&status_list, status_list_issuer_params.clone()).unwrap();
        verifier.insert_status_in_cache(&status_uri, status_token_invalid_index.to_cbor_bytes().unwrap(), &cks);
        let err = verifier
            .verify_sd_kbt_with_status(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::StatusInvalid(uri)) if uri == status_uri));

        // 4. index is out of bounds
        let short_status_list = StatusList::<OauthStatus>::with_capacity(1 << 6, None);
        let short_status_token = status_issuer.issue_status_list_token(&short_status_list, status_list_issuer_params.clone()).unwrap();
        verifier.insert_status_in_cache(&status_uri, short_status_token.to_cbor_bytes().unwrap(), &cks);
        let err = verifier
            .verify_sd_kbt_with_status(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
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
        verifier.insert_status_in_cache(&status_uri, status_token.to_cbor_bytes().unwrap(), &cks);

        verifier
            .verify_sd_kbt_with_status(&sd_kbt, verifier_params, status_list_verifier_params, None, &cks, status_list_cks)
            .await
            .unwrap();

        // 6. should fail if status_token not signed by expected issuer
        let fake_status_token_signer = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let fake_status_list_cks = CoseKeySet::builder().with(&fake_status_token_signer.verifying_key()).unwrap().build();
        let err = verifier.verify_status_token(&status_token.to_cbor_bytes().unwrap(), &fake_status_list_cks).unwrap_err();
        assert!(matches!(err, SdCwtVerifierError::StatusError(SdCwtStatusVerifierError::InvalidStatusTokenSignature(_))));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_reject_orphan_disclosure() {
        use crate::spec::{
            Salt,
            blinded_claims::{SaltedElement, SaltedEntry},
        };

        let payload = CustomTokenClaims {
            name: Some("Alice Smith".into()),
            stuffs: vec![Stuff { foo: "bar".into() }],
        };
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::new(issuer_signing_key.clone());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);

        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issuer_params.clone()).unwrap().to_cbor_bytes().unwrap();
        let holder = Ed25519Holder::<Value, NoClaims>::new(holder_signing_key.clone());
        let cks = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
        let mut sd_cwt = holder.verify_sd_cwt(&sd_cwt, Default::default(), &cks).unwrap();

        let orphan = SaltedEntry::Element(SaltedElement {
            salt: Salt::empty(),
            value: Stuff { foo: "baz".into() }.to_cbor_value().unwrap(),
        });
        sd_cwt.0.sd_unprotected.sd_claims.as_mut().unwrap().push(orphan.into());

        let holder_params = default_holder_params::<NoClaims>();
        let sd_kbt = holder.new_presentation(sd_cwt, holder_params).unwrap().to_cbor_bytes().unwrap();

        let verifier = HybridVerifier::<CustomTokenClaims, NoClaims>::default();
        let err = verifier
            .verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_signing_key.verifying_key()), &cks)
            .unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::OrphanDisclosure);
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_reject_duplicate_claim_name() {
        let payload = cbor!({sd!("dup") => "a", sd!("dup") => "b"}).unwrap();

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer_params = default_issuer_params(Some(payload), &holder_signing_key);
        let err = verify(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key).unwrap_err();
        std::assert_matches!(err, SdCwtVerifierError::DuplicateMapKeys);
    }

    mod expected_claims {
        use super::*;

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn kbt_cnonce() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);

            // Holder builds a presentation without a cnonce
            let mut holder_params = default_holder_params::<NoClaims>();
            holder_params.cnonce = Some(b"aaa");

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, holder_params, &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_cnonce: Some(b"bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::CnonceMismatch { actual, expected } if expected == b"bbb" && actual == b"aaa");
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn missing_kbt_cnonce() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);

            // Holder builds a presentation without a cnonce
            let mut holder_params = default_holder_params::<NoClaims>();
            holder_params.cnonce = None;

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, holder_params, &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_cnonce: Some(b"cnonce"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::CnonceMismatch { actual, expected } if expected == b"cnonce" && actual.is_empty());
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn sub() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.subject = Some("aaa");

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_subject: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::SubMismatch { actual, expected } if &expected == "bbb" && &actual == "aaa");
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn missing_sub() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.subject = None;

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_subject: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::SubMismatch { actual, expected } if &expected == "bbb" && actual.is_empty());
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn audience() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.audience = Some("aaa");

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_audience: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::AudienceMismatch { actual, expected } if &expected == "bbb" && &actual == "aaa");
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn missing_aud() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.audience = None;

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_audience: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::AudienceMismatch { actual, expected } if &expected == "bbb" && actual.is_empty());
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn kbt_audience() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);

            let mut holder_params = default_holder_params::<NoClaims>();
            holder_params.audience = "aaa";

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, holder_params, &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_kbt_audience: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::KbtAudienceMismatch { actual, expected } if &expected == "bbb" && &actual == "aaa");
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn issuer() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.issuer = "aaa";

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();

            let params = VerifierParams {
                expected_issuer: Some("bbb"),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::IssuerMismatch { actual, expected } if &expected == "bbb" && &actual == "aaa");
        }
    }

    mod time {
        use super::*;

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn verify_sd_cwt_expiry() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            // Issuer issues an SD-CWT valid for only 5 seconds
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.expiry = Some(TimeArg::Relative(core::time::Duration::from_secs(5)));

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();
            let later = (elapsed_since_epoch().as_secs() + 20) as i64;
            let params = VerifierParams {
                artificial_time: Some(later),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::TimeError(CwtTimeError::Expired));
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn verify_sd_cwt_iat() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.with_issued_at = true;
            issuer_params.with_not_before = false;

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();
            let past = (elapsed_since_epoch().as_secs() - 20) as i64;
            let params = VerifierParams {
                artificial_time: Some(past),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::TimeError(CwtTimeError::ClockDrift));
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn verify_sd_cwt_nbf() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.with_not_before = true;
            issuer_params.with_issued_at = false;

            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, default_holder_params::<NoClaims>(), &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();
            let past = (elapsed_since_epoch().as_secs() - 20) as i64;
            let params = VerifierParams {
                artificial_time: Some(past),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::TimeError(CwtTimeError::NotValidYet));
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn verify_sd_kbt_expiry() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

            let issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);

            // SD-KBT valid for only 5 seconds
            let mut params = default_holder_params::<NoClaims>();
            params.expiry = Some(TimeArg::Relative(core::time::Duration::from_secs(5)));
            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, params, &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();
            let later = (elapsed_since_epoch().as_secs() + 20) as i64;
            let params = VerifierParams {
                artificial_time: Some(later),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::TimeError(CwtTimeError::Expired));
        }

        #[test]
        #[wasm_bindgen_test::wasm_bindgen_test]
        fn verify_sd_kbt_nbf() {
            let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let mut issuer_params = default_issuer_params(None::<Value>, &holder_signing_key);
            issuer_params.expiry = None;
            issuer_params.with_issued_at = false;
            issuer_params.with_not_before = false;

            let mut params = default_holder_params::<NoClaims>();
            params.with_not_before = true;
            let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params, params, &holder_signing_key);
            let verifier = HybridVerifier::<Value, NoClaims>::default();
            let past = (elapsed_since_epoch().as_secs() - 20) as i64;
            let params = VerifierParams {
                artificial_time: Some(past),
                ..Default::default()
            };
            let err = verifier.verify_sd_kbt(&sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks).unwrap_err();
            std::assert_matches!(err, SdCwtVerifierError::TimeError(CwtTimeError::NotValidYet));
        }
    }

    fn verify<T: Select, U: CustomClaims>(
        issuer_params: IssuerParams<T>,
        holder_params: HolderParams<U>,
        holder_signing_key: &ed25519_dalek::SigningKey,
    ) -> Result<KbtCwtVerified<T, U>, SdCwtVerifierError<Infallible>> {
        let (cks, sd_kbt, ..) = generate_sd_kbt(issuer_params.clone(), holder_params, holder_signing_key);
        let verifier = HybridVerifier::<T, U>::default();
        verifier.verify_sd_kbt(&sd_kbt, Default::default(), Some(&holder_signing_key.verifying_key()), &cks)
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
        let cks = CoseKeySet::builder().with_signing_key(&issuer_signing_key).unwrap().build();
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
    use crate::spec::{Redact, Select};
    use ciborium::Value;

    #[derive(Default, Debug, Clone, PartialEq, serde::Serialize)]
    pub struct CustomTokenClaims {
        pub name: Option<String>,
        pub(super) stuffs: Vec<Stuff>,
    }

    impl<'de> serde::Deserialize<'de> for CustomTokenClaims {
        fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let mut token = Self::default();
            let value = Value::deserialize(deserializer)?.into_map().unwrap();
            for (k, v) in value {
                match (&k, v) {
                    (Value::Text(s), Value::Text(name)) if *s == "name" => {
                        token.name.replace(name);
                    }
                    (Value::Text(s), Value::Array(values)) if *s == "stuffs" => {
                        let values = values.into_iter().filter(|v| !matches!(v, Value::Tag(_, _))).collect::<Vec<_>>();
                        token.stuffs = Value::Array(values).deserialized().unwrap();
                    }
                    _ => {}
                }
            }
            Ok(token)
        }
    }

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub(super) struct Stuff {
        pub foo: String,
    }

    impl Select for CustomTokenClaims {
        fn select(self) -> Result<Value, ciborium::value::Error> {
            let mut values = Value::serialized(&self)?.into_map().unwrap();
            for (label, value) in &mut values {
                let mut label = label;
                match (&label, value) {
                    (Value::Text(s), _) if *s == "name" => label.redact(),
                    (Value::Text(s), values) if *s == "stuffs" => {
                        values.as_array_mut().into_iter().flatten().for_each(|mut v| v.redact());
                    }
                    _ => {}
                };
            }
            Ok(Value::Map(values))
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use super::*;
    use crate::spec::NoClaims;
    use status_list::OauthStatus;
    use std::collections::HashMap;
    use url::Url;

    // TODO: turn generic again
    #[allow(dead_code)]
    #[derive(Debug, Clone)]
    pub struct HybridVerifier<DisclosedClaims: CustomClaims, KbtClaims: CustomClaims = NoClaims> {
        pub status_cache: HashMap<String, std::sync::Arc<VerifiedStatusListToken<OauthStatus>>>,
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

        pub(crate) fn insert_status_in_cache(&mut self, status_url: &Url, status_token: Vec<u8>, status_list_cks: &cose_key::keyset::CoseKeySet) {
            let status_token = self.verify_status_token(&status_token, status_list_cks).unwrap();
            self.status_cache.entry(status_url.to_string()).insert_entry(status_token.into());
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
        type Status = OauthStatus;

        fn get_status_token(
            &self,
            status_url: &str,
            _status_list_cks: &cose_key::keyset::CoseKeySet,
        ) -> impl Future<Output = Result<Option<std::sync::Arc<VerifiedStatusListToken<Self::Status>>>, SdCwtVerifierError<Self::Error>>> + Send {
            std::future::ready(self.status_cache.get(status_url).cloned().map(Ok).transpose())
        }
    }
}

#[cfg(test)]
mod backward {
    use super::*;
    use crate::{
        TimeVerification,
        snapshots::SdKbtSnapshots,
        spec::NoClaims,
        verifier::{claims::CustomTokenClaims, test_utils::HybridVerifier},
    };
    use cose_key::keyset::CoseKeySet;
    use strum::IntoEnumIterator as _;

    #[test]
    fn should_work_with_snapshot_sd_kbt() {
        for snapshot in SdKbtSnapshots::iter() {
            match snapshot {
                #[cfg(feature = "backward")]
                SdKbtSnapshots::FullDraft08 | SdKbtSnapshots::NoneDraft08 => sd_kbt_verification::<CustomTokenClaims>(&snapshot.sd_kbt()),
                SdKbtSnapshots::Full | SdKbtSnapshots::None => sd_kbt_verification::<CustomTokenClaims>(&snapshot.sd_kbt()),
            }
            .inspect_err(|err: &anyhow::Error| panic!("'{snapshot:?}' failed because: {err:?}"))
            .unwrap();
        }
    }

    fn sd_kbt_verification<T: Select>(sd_kbt: &[u8]) -> anyhow::Result<()> {
        let mut rng = dernged::Rng::default();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rng);
        let cks = CoseKeySet::builder().with(&issuer_signing_key.verifying_key())?.build();
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rng);

        let verifier = HybridVerifier::<T, NoClaims>::default();
        let params = VerifierParams {
            sd_cwt_time_verification: TimeVerification {
                verify_exp: false,
                verify_iat: false,
                verify_nbf: false,
            },
            sd_kbt_time_verification: TimeVerification {
                verify_exp: false,
                verify_iat: false,
                verify_nbf: false,
            },
            ..Default::default()
        };
        verifier.verify_sd_kbt(sd_kbt, params, Some(&holder_signing_key.verifying_key()), &cks)?;

        Ok(())
    }
}
