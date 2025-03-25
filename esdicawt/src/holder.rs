use crate::{HolderParams, SdCwtHolderError, now};
use esdicawt_spec::{
    CustomClaims, CwtAny, SdHashAlg, Select,
    issuance::SdCwtIssuedTagged,
    key_binding::{KbtCwtTagged, KbtPayload, KbtProtected, KbtUnprotected},
    reexports::coset::{
        TaggedCborSerializable, {self},
    },
};
use signature::Signer;

pub mod error;
pub mod params;
pub mod traverse;

pub trait Holder {
    type Error: core::error::Error + Send + Sync;

    type Signature;
    type Hasher: digest::Digest;

    #[cfg(not(any(feature = "pem", feature = "der")))]
    type Signer: Signer<Self::Signature>;

    #[cfg(any(feature = "pem", feature = "der"))]
    type Signer: Signer<Self::Signature> + pkcs8::DecodePrivateKey;

    type IssuerPayloadClaims: Select;
    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtUnprotectedClaims: CustomClaims;
    type KbtPayloadClaims: CustomClaims;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm;
    fn hash_algorithm(&self) -> SdHashAlg;

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

    fn serialize_signature(&self, signature: &Self::Signature) -> Result<Vec<u8>, Self::Error>;

    /// Simple API when a holder wants all the redacted claims to be disclosed to the Verifier
    #[allow(clippy::type_complexity)]
    fn new_presentation(
        &self,
        sd_cwt_issued: &[u8],
        params: HolderParams<Self::KbtProtectedClaims, Self::KbtUnprotectedClaims, Self::KbtPayloadClaims>,
    ) -> Result<
        KbtCwtTagged<
            Self::IssuerPayloadClaims,
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
        >,
        SdCwtHolderError<Self::Error>,
    > {
        let mut sd_cwt_issued = SdCwtIssuedTagged::from_cbor_bytes(sd_cwt_issued)?;

        // --- building the kbt ---
        // --- unprotected ---
        let unprotected = KbtUnprotected {
            extra: params.extra_kbt_unprotected,
        }
        .try_into()?;

        // --- redaction of claims ---
        // select the claims to disclose
        let sd_claims = params
            .presentation
            .try_select_disclosures::<Self::Hasher, Self::Error>(sd_cwt_issued.0.sd_unprotected.sd_claims)?;

        // then replace them in the issued sd-cwt
        sd_cwt_issued.0.sd_unprotected.sd_claims = sd_claims;

        // --- protected ---
        let alg = coset::Algorithm::Assigned(self.cwt_algorithm());
        let protected = KbtProtected::<Self::IssuerPayloadClaims, Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims, Self::KbtProtectedClaims> {
            alg: alg.into(),
            kcwt: sd_cwt_issued.into(),
            extra: params.extra_kbt_protected,
        }
        .try_into()
        .map_err(|_| SdCwtHolderError::ImplementationError("Failed mapping kbt protected to COSE header"))?;

        // --- payload ---
        #[cfg(feature = "test-vectors")]
        let now = params.now.map(|d| d.as_secs()).unwrap_or_else(now);
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
            cnonce: None,
            extra: params.extra_kbt_payload,
        };

        let sign1 = coset::CoseSign1Builder::new()
            .protected(protected)
            .unprotected(unprotected)
            .payload(payload.to_cbor_bytes()?)
            .try_create_signature(&[], |tbs| {
                let signature = self.signer().try_sign(tbs)?;
                self.serialize_signature(&signature).map_err(SdCwtHolderError::CustomError)
            })?
            .build()
            .to_tagged_vec()?;
        Ok(KbtCwtTagged::from_cbor_bytes(&sign1)?)
    }
}

#[cfg(test)]
mod tests {
    use super::{claims::CustomTokenClaims, test_utils::Ed25519Holder, *};
    use crate::{Issuer, IssuerParams, Presentation, holder::params::CborPath, issuer::test_utils::Ed25519IssuerClaims};
    use ciborium::cbor;
    use esdicawt_spec::{
        ClaimName, NoClaims,
        blinded_claims::{Salted, SaltedClaim},
    };
    use rand_core::SeedableRng as _;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_succeed() {
        let mut csprng = rand_chacha::ChaCha20Rng::from_entropy();

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut csprng);
        let issuer = Ed25519IssuerClaims::<CustomTokenClaims>::new(issuer_signing_key);

        let payload = CustomTokenClaims {
            name: Some("Alice Smith".into()),
            age: Some(42),
        };
        let issue_params = IssuerParams {
            protected_claims: None,
            unprotected_claims: None,
            payload: Some(payload),
            issuer: "mimi://example.com/i/acme.io",
            subject: Some("mimi://example.com/u/alice.smith"),
            audience: Default::default(),
            cti: Default::default(),
            cnonce: Default::default(),
            key_location: "https://auth.acme.io/issuer.cwk",
            expiry: Some(core::time::Duration::from_secs(90)),
            with_not_before: false,
            with_issued_at: false,
            leeway: core::time::Duration::from_secs(1),
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
            now: None,
        };
        let sd_cwt = issuer.issue_cwt(&mut csprng, issue_params).unwrap().to_cbor_bytes().unwrap();

        let holder = Ed25519Holder::<CustomTokenClaims>::new(holder_signing_key);

        let presentation = Presentation::Path(Box::new(|path| match path {
            [CborPath::Str(name), ..] if name == "name" => true,
            [CborPath::Str(age), ..] if age == "age" => false,
            _ => false,
        }));

        let presentation_params = HolderParams {
            presentation,
            audience: "mimi://example.com/r/alice-bob-group",
            expiry: Some(core::time::Duration::from_secs(90 * 24 * 3600)),
            with_not_before: false,
            leeway: core::time::Duration::from_secs(3600),
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
            now: None,
        };

        let mut sd_cwt_kbt = holder.new_presentation(&sd_cwt, presentation_params).unwrap();

        let sd_cwt_kbt_2 = sd_cwt_kbt.to_cbor_bytes().unwrap();
        let sd_cwt_kbt_2 = KbtCwtTagged::from_cbor_bytes(&sd_cwt_kbt_2).unwrap();
        assert_eq!(sd_cwt_kbt, sd_cwt_kbt_2);

        let disclosable_claims = sd_cwt_kbt.0.walk_disclosed_claims().unwrap().collect::<Vec<_>>();
        assert_eq!(disclosable_claims.len(), 1);
        let is_alice = |sc: &SaltedClaim<ciborium::Value>| sc.name == ClaimName::Text("name".into()) && sc.value == cbor!("Alice Smith").unwrap();

        assert!(disclosable_claims.into_iter().any(|c| { matches!(c.unwrap(), Salted::Claim(sc) if is_alice(sc)) }));
    }

    #[allow(dead_code, unused_variables)]
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
                    Hasher = sha2::Sha256,
                >,
        >,
    ) {
    }
}

#[cfg(test)]
pub mod claims {
    use ciborium::Value;
    use esdicawt_spec::{EsdicawtSpecError, Select, sd};

    #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
    pub(super) struct CustomTokenClaims {
        pub name: Option<String>,
        pub age: Option<u32>,
    }

    impl Select for CustomTokenClaims {
        type Error = EsdicawtSpecError;

        fn select(self) -> Result<Value, <Self as Select>::Error> {
            let mut map = Vec::with_capacity(2);
            if let Some(name) = self.name {
                map.push((sd(Value::Text("name".into())), Value::Text(name)));
            }
            if let Some(age) = self.age {
                map.push((sd(Value::Text("age".into())), Value::Integer(age.into())));
            }
            Ok(Value::Map(map))
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use esdicawt_spec::{CustomClaims, NoClaims, Select, reexports::coset};

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Ed25519Holder<DisclosedClaims: CustomClaims> {
        signing_key: ed25519_dalek::SigningKey,
        pub _marker: core::marker::PhantomData<DisclosedClaims>,
    }

    impl<T: Select> super::Holder for Ed25519Holder<T>
    where
        ed25519_dalek::SigningKey: signature::Signer<ed25519_dalek::Signature>,
    {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Signature = ed25519_dalek::Signature;
        type Hasher = sha2::Sha256;

        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = T;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn serialize_signature(&self, signature: &Self::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(ed25519_dalek::Signature::to_bytes(signature).into())
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> esdicawt_spec::SdHashAlg {
            esdicawt_spec::SdHashAlg::Sha256
        }
    }
}
