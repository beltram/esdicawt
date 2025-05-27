use crate::{
    HolderParams, HolderValidationParams, SdCwtHolderError, SdCwtHolderValidationError,
    holder::validation::validate_disclosures,
    now,
    signature_verifier::validate_signature,
    spec::{
        CustomClaims, CwtAny, NoClaims, Select,
        issuance::SdCwtIssuedTagged,
        key_binding::{KbtCwtTagged, KbtPayload, KbtProtected, KbtUnprotected},
        reexports::coset::{
            CoseSign1, TaggedCborSerializable, {self},
        },
    },
};
use ciborium::Value;
use cose_key_confirmation::{KeyConfirmation, error::CoseKeyConfirmationError};

pub mod error;
pub mod params;
pub mod traverse;
pub mod validation;

pub trait Holder {
    type Error: core::error::Error + Send + Sync;

    type Hasher: digest::Digest + Clone;

    #[cfg(not(any(feature = "pem", feature = "der")))]
    type Signer: signature::Signer<Self::Signature>;

    #[cfg(any(feature = "pem", feature = "der"))]
    type Signer: signature::Signer<Self::Signature> + pkcs8::DecodePrivateKey;

    type Signature: signature::SignatureEncoding;
    type Verifier: signature::Verifier<Self::Signature> + PartialEq + for<'a> TryFrom<&'a KeyConfirmation, Error = CoseKeyConfirmationError>;

    type IssuerPayloadClaims: Select;
    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtUnprotectedClaims: CustomClaims;
    type KbtPayloadClaims: CustomClaims;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm;

    /// Build a new instance of a Holder by providing a signing key
    fn new(signing_key: Self::Signer) -> Self
    where
        Self: Sized;

    #[cfg(feature = "pem")]
    fn try_from_pem(pem: &str) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = Self::Signer::from_pkcs8_pem(pem)?;
        Ok(Self::new(signer))
    }

    #[cfg(feature = "der")]
    fn try_from_der(der: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
        Self::Error: From<pkcs8::Error>,
    {
        use pkcs8::DecodePrivateKey as _;
        let signer = Self::Signer::from_pkcs8_der(der)?;
        Ok(Self::new(signer))
    }

    fn signer(&self) -> &Self::Signer;

    fn verifier(&self) -> &Self::Verifier;

    // TODO: there are no unblinded claims about the subject which violate its privacy policies
    // TODO: all the Salted Disclosed Claims are correct in their unblinded context in the payload
    #[allow(clippy::type_complexity)]
    fn verify_sd_cwt(
        &self,
        sd_cwt: &[u8],
        params: HolderValidationParams,
        keyset: &cose_key_set::CoseKeySet,
    ) -> Result<SdCwtVerified<Self::IssuerPayloadClaims, Self::Hasher, Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims>, SdCwtHolderError<Self::Error>> {
        let cose_sign1_sd_cwt = CoseSign1::from_tagged_slice(sd_cwt)?;

        validate_signature(&cose_sign1_sd_cwt, keyset)?;

        let mut sd_cwt = SdCwtIssuedTagged::from_cbor_bytes(sd_cwt)?;
        let payload = sd_cwt.0.payload.to_value()?;

        // verify time claims
        #[cfg(not(feature = "test-vectors"))] // FIXME: draft samples are expired
        {
            let now = params.artificial_time.unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp());
            crate::time::verify_time_claims(now, params.leeway, payload.inner.issued_at, payload.inner.expiration, payload.inner.not_before)?;
        }

        // subject
        if let Some((actual, expected)) = payload.inner.subject.as_ref().zip(params.expected_subject) {
            if actual != expected {
                return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::SubMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                }));
            }
        }

        // issuer
        if let Some(expected) = params.expected_issuer {
            let actual = &payload.inner.issuer;
            if actual != expected {
                return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::IssuerMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                }));
            }
        }

        // audience
        if let Some((actual, expected)) = payload.inner.audience.as_ref().zip(params.expected_audience) {
            if actual != expected {
                return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::AudienceMismatch {
                    actual: actual.to_owned(),
                    expected: expected.to_owned(),
                }));
            }
        }

        // cnonce
        if let Some((actual, expected)) = payload.inner.cnonce.as_ref().zip(params.expected_cnonce) {
            if actual != expected {
                return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::CnonceMismatch {
                    actual: actual.to_vec(),
                    expected: expected.to_owned(),
                }));
            }
        }

        // key confirmation
        let expected = self.verifier();
        let actual: Self::Verifier = (&payload.cnf).try_into()?;
        if actual != *expected {
            return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::VerifyingKeyMismatch));
        }

        // validate disclosure
        let disclosures = sd_cwt.0.disclosures();
        if let Some((raw_payload, disclosures)) = cose_sign1_sd_cwt.payload.as_deref().map(Value::from_cbor_bytes).transpose()?.zip(disclosures) {
            let actual_nb_disclosures = disclosures.digested::<Self::Hasher>()?;

            let expected_nb_disclosures = validate_disclosures(&raw_payload, &actual_nb_disclosures)?;

            if expected_nb_disclosures != actual_nb_disclosures.len() {
                return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure {
                    expected: expected_nb_disclosures,
                    actual: actual_nb_disclosures.len(),
                }));
            }
        } else if disclosures.map(|d| !d.is_empty()).unwrap_or_default() {
            // SAFETY: we already checked 'disclosures' is Some
            let actual = disclosures.unwrap().len();
            return Err(SdCwtHolderError::ValidationError(SdCwtHolderValidationError::OrphanDisclosure { expected: 0, actual }));
        }

        Ok(SdCwtVerified(sd_cwt))
    }

    /// Simple API when a holder wants all the redacted claims to be disclosed to the Verifier
    #[allow(clippy::type_complexity)]
    fn new_presentation_raw(
        &self,
        mut sd_cwt: SdCwtVerified<Self::IssuerPayloadClaims, Self::Hasher, Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims>,
        params: HolderParams<Self::KbtPayloadClaims, Self::KbtProtectedClaims, Self::KbtUnprotectedClaims>,
    ) -> Result<Vec<u8>, SdCwtHolderError<Self::Error>> {
        // verify time claims first
        #[cfg(not(feature = "test-vectors"))] // FIXME: draft samples are expired
        {
            let payload = sd_cwt.0.0.payload.clone_value()?;
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            crate::time::verify_time_claims(now, params.leeway, payload.inner.issued_at, payload.inner.expiration, payload.inner.not_before)?;
        }

        // --- building the kbt ---
        // --- unprotected ---
        let unprotected = KbtUnprotected {
            extra: params.extra_kbt_unprotected,
        }
        .try_into()?;

        // --- redaction of claims ---
        // select the claims to disclose
        if let Some(sd_claims) = sd_cwt.0.0.sd_unprotected.sd_claims {
            let sd_claims = params.presentation.try_select_disclosures::<Self::Hasher, Self::Error>(sd_claims)?;

            // then replace them in the issued sd-cwt
            sd_cwt.0.0.sd_unprotected.sd_claims = Some(sd_claims);
        }

        // --- protected ---
        let alg = coset::Algorithm::Assigned(self.cwt_algorithm());
        let protected = KbtProtected::<Self::IssuerPayloadClaims, Self::Hasher, Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims, Self::KbtProtectedClaims> {
            alg: alg.into(),
            kcwt: sd_cwt.0.into(),
            extra: params.extra_kbt_protected,
        }
        .try_into()
        .map_err(|_| SdCwtHolderError::ImplementationError("Failed mapping kbt protected to COSE header"))?;

        // --- payload ---
        #[cfg(feature = "test-vectors")]
        let now = params.artificial_time.map(|d| d.as_secs()).unwrap_or_else(now);
        #[cfg(not(feature = "test-vectors"))]
        let now = now();

        let expiration = params.expiry.map(|exp| (now + exp.as_secs()) as i64);
        let not_before = params.with_not_before.then_some(now as i64);
        let issued_at = now as i64;

        let payload = KbtPayload {
            audience: params.audience.to_string(),
            expiration,
            not_before,
            issued_at,
            cnonce: params.cnonce.map(|b| b.to_owned().into()),
            extra: params.extra_kbt_payload,
        };

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_cbor_bytes()?)
            .try_create_signature(&[], |tbs| {
                use signature::{SignatureEncoding as _, Signer as _};
                let signature = self.signer().try_sign(tbs)?;
                Result::<_, signature::Error>::Ok(signature.to_bytes().as_ref().to_vec())
            })?
            .build()
            .to_tagged_vec()?;
        Ok(sign1)
    }

    /// Simple API when a holder wants all the redacted claims to be disclosed to the Verifier
    #[allow(clippy::type_complexity)]
    fn new_presentation(
        &self,
        sd_cwt: SdCwtVerified<Self::IssuerPayloadClaims, Self::Hasher, Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims>,
        params: HolderParams<Self::KbtPayloadClaims, Self::KbtProtectedClaims, Self::KbtUnprotectedClaims>,
    ) -> Result<
        KbtCwtTagged<
            Self::IssuerPayloadClaims,
            Self::Hasher,
            Self::KbtPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
        >,
        SdCwtHolderError<Self::Error>,
    > {
        let sign1 = self.new_presentation_raw(sd_cwt, params)?;
        Ok(KbtCwtTagged::from_cbor_bytes(&sign1)?)
    }
}

#[derive(Debug, Clone)]
pub struct SdCwtVerified<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims>(
    pub SdCwtIssuedTagged<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
);

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> PartialEq
    for SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{claims::CustomTokenClaims, test_utils::Ed25519Holder, *};
    use crate::{CwtStdLabel, Issuer, IssuerParams, Presentation, holder::params::CborPath, issuer::test_utils::Ed25519Issuer};
    use ciborium::cbor;
    use cose_key_set::CoseKeySet;
    use esdicawt_spec::{
        ClaimName, NoClaims,
        blinded_claims::{Salted, SaltedClaim},
    };
    use std::collections::HashMap;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_succeed() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder_verifying_key = holder_signing_key.verifying_key();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::<CustomTokenClaims>::new(issuer_signing_key.clone());

        let payload = CustomTokenClaims {
            name: Some("Alice Smith".into()),
            age: Some(42),
            array: vec!["a".into()],
            map: HashMap::from_iter([("a".into(), "b".into())]),
        };
        let issue_params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: Some(payload),
            issuer: "https://example.com/i/acme.io",
            subject: Some("https://example.com/u/alice.smith"),
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            key_location: "https://auth.acme.io/issuer.cwk",
            expiry: Some(core::time::Duration::from_secs(90)),
            with_not_before: false,
            with_issued_at: false,
            leeway: core::time::Duration::from_secs(1),
            holder_confirmation_key: (&holder_verifying_key).try_into().unwrap(),
            artificial_time: None,
        };
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issue_params).unwrap().to_cbor_bytes().unwrap();

        let holder = Ed25519Holder::<CustomTokenClaims, NoClaims>::new(holder_signing_key);

        let presentation = Presentation::Path(Box::new(|path| match path {
            [CborPath::Str(name), ..] if name == "name" => true,
            [CborPath::Str(age), ..] if age == "age" => false,
            _ => false,
        }));

        let presentation_params = HolderParams {
            presentation,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: None,
            expiry: Some(core::time::Duration::from_secs(90 * 24 * 3600)),
            with_not_before: false,
            leeway: core::time::Duration::from_secs(3600),
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
            artificial_time: None,
        };

        let sd_cwt = holder.verify_sd_cwt(&sd_cwt, Default::default(), &CoseKeySet::new(&issuer_signing_key).unwrap()).unwrap();

        let mut sd_kbt = holder.new_presentation(sd_cwt, presentation_params).unwrap();

        let sd_kbt_2 = sd_kbt.to_cbor_bytes().unwrap();
        let sd_kbt_2 = KbtCwtTagged::<CustomTokenClaims, sha2::Sha256>::from_cbor_bytes(&sd_kbt_2).unwrap();
        assert_eq!(sd_kbt.to_cbor_bytes().unwrap(), sd_kbt_2.to_cbor_bytes().unwrap());

        let disclosable_claims = sd_kbt.0.walk_disclosed_claims().unwrap().collect::<Vec<_>>();
        assert_eq!(disclosable_claims.len(), 1);
        let is_alice = |sc: &SaltedClaim<ciborium::Value>| sc.name == ClaimName::Text("name".into()) && sc.value == cbor!("Alice Smith").unwrap();

        assert!(disclosable_claims.into_iter().any(|c| { matches!(c.unwrap(), Salted::Claim(sc) if is_alice(sc)) }));
    }

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_generate_valid_sd_kbt() {
        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let holder_verifying_key = holder_signing_key.verifying_key();
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::<CustomTokenClaims>::new(issuer_signing_key.clone());

        let issue_params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: None,
            issuer: "https://example.com/i/acme.io",
            subject: Some("https://example.com/u/alice.smith"),
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            key_location: "https://auth.acme.io/issuer.cwk",
            expiry: Some(core::time::Duration::from_secs(90)),
            with_not_before: false,
            with_issued_at: false,
            leeway: core::time::Duration::from_secs(1),
            holder_confirmation_key: (&holder_verifying_key).try_into().unwrap(),
            artificial_time: None,
        };
        let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), issue_params).unwrap().to_cbor_bytes().unwrap();

        let holder = Ed25519Holder::<CustomTokenClaims, NoClaims>::new(holder_signing_key);
        let presentation_params = HolderParams {
            presentation: Presentation::Full,
            audience: "https://example.com/r/alice-bob-group",
            cnonce: Some(b"cnonce"),
            expiry: Some(core::time::Duration::from_secs(90 * 24 * 3600)),
            with_not_before: true,
            leeway: core::time::Duration::from_secs(3600),
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
            artificial_time: None,
        };
        let sd_cwt = holder.verify_sd_cwt(&sd_cwt, Default::default(), &CoseKeySet::new(&issuer_signing_key).unwrap()).unwrap();
        let sd_kbt_bytes = holder.new_presentation(sd_cwt, presentation_params).unwrap().to_cbor_bytes().unwrap();
        let raw_sd_kbt = CoseSign1::from_tagged_slice(&sd_kbt_bytes).unwrap();
        let payload = Value::from_cbor_bytes(&raw_sd_kbt.payload.unwrap()).unwrap().into_map().unwrap();

        for entry in payload {
            match entry {
                (Value::Integer(label), Value::Text(aud)) if label == CwtStdLabel::Audience => assert_eq!(&aud, "https://example.com/r/alice-bob-group"),
                (Value::Integer(label), Value::Integer(_)) if label == CwtStdLabel::ExpiresAt => {}
                (Value::Integer(label), Value::Integer(_)) if label == CwtStdLabel::IssuedAt => {}
                (Value::Integer(label), Value::Integer(_)) if label == CwtStdLabel::NotBefore => {}
                (Value::Integer(label), Value::Bytes(cnonce)) if label == CwtStdLabel::Cnonce => assert_eq!(cnonce, b"cnonce"),
                e => panic!("unexpected: {e:?}"),
            }
        }
    }

    #[allow(dead_code, unused_variables, clippy::type_complexity)]
    fn should_be_object_safe(
        holder: Box<
            dyn Holder<
                    IssuerProtectedClaims = NoClaims,
                    IssuerUnprotectedClaims = NoClaims,
                    IssuerPayloadClaims = NoClaims,
                    KbtProtectedClaims = NoClaims,
                    KbtUnprotectedClaims = NoClaims,
                    KbtPayloadClaims = NoClaims,
                    Error = std::convert::Infallible,
                    Signer = ed25519_dalek::SigningKey,
                    Signature = ed25519_dalek::Signature,
                    Verifier = ed25519_dalek::VerifyingKey,
                    Hasher = sha2::Sha256,
                >,
        >,
    ) {
    }

    #[allow(dead_code)]
    fn should_be_comparable<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims>(
        a: SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
        b: SdCwtVerified<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
    ) -> bool {
        a == b
    }
}

#[cfg(test)]
pub mod claims {
    use ciborium::Value;
    use esdicawt_spec::{Select, sd};
    use std::collections::HashMap;

    #[derive(Default, Debug, Clone, PartialEq, serde::Serialize)]
    pub(super) struct CustomTokenClaims {
        pub name: Option<String>,
        pub age: Option<u32>,
        pub array: Vec<String>,
        pub map: HashMap<String, String>,
    }

    impl<'de> serde::Deserialize<'de> for CustomTokenClaims {
        fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let value = <Value as serde::Deserialize>::deserialize(deserializer)?.into_map().unwrap();
            let mut model = Self::default();

            for entry in value {
                match entry {
                    (Value::Text(l), Value::Text(name)) if l == "name" => {
                        model.name.replace(name);
                    }
                    (Value::Text(l), Value::Integer(age)) if l == "age" => {
                        model.age.replace(age.try_into().unwrap());
                    }
                    (Value::Text(l), Value::Array(array)) if l == "array" => {
                        model.array = array.into_iter().filter_map(|v| v.into_text().ok()).collect();
                    }
                    (Value::Text(l), Value::Map(map)) if l == "map" => {
                        model.map = map.into_iter().filter_map(|(k, v)| k.into_text().ok().zip(v.into_text().ok())).collect();
                    }
                    _ => unreachable!(),
                }
            }

            Ok(model)
        }
    }

    impl Select for CustomTokenClaims {
        fn select(self) -> Result<Value, ciborium::value::Error> {
            let mut map = Vec::with_capacity(4);
            if let Some(name) = self.name {
                map.push((sd!("name"), Value::Text(name)));
            }
            if let Some(age) = self.age {
                map.push((sd!("age"), Value::Integer(age.into())));
            }

            let array = self.array.clone().into_iter().map(|e| sd!(e)).collect();
            map.push((Value::Text("array".into()), Value::Array(array)));

            let inner = self.map.clone().into_iter().map(|(k, v)| (sd!(Value::from(k)), v.into())).collect();
            map.push((Value::Text("map".into()), Value::Map(inner)));

            Ok(Value::Map(map))
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use crate::spec::{CustomClaims, NoClaims, Select, reexports::coset};

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Ed25519Holder<DisclosedClaims: CustomClaims, KbtClaims: CustomClaims> {
        signing_key: ed25519_dalek::SigningKey,
        verifying_key: ed25519_dalek::VerifyingKey,
        pub _marker: core::marker::PhantomData<(DisclosedClaims, KbtClaims)>,
    }

    impl<T: Select, U: CustomClaims> super::Holder for Ed25519Holder<T, U>
    where
        ed25519_dalek::SigningKey: signature::Signer<ed25519_dalek::Signature>,
    {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;

        type Signature = ed25519_dalek::Signature;
        type Verifier = ed25519_dalek::VerifyingKey;

        type IssuerPayloadClaims = T;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type KbtPayloadClaims = U;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                verifying_key: signing_key.verifying_key(),
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn verifier(&self) -> &Self::Verifier {
            &self.verifying_key
        }
    }
}
