use crate::{CwtPresentationParams, Presentation, SdCwtHolderError, now};
use esdicawt_spec::{
    CustomClaims, CwtAny, SelectiveDisclosureHashAlg,
    blinded_claims::SaltedArray,
    issuance::SelectiveDisclosureIssuedTagged,
    key_binding::{KeyBindingTokenPayload, KeyBindingTokenProtected, KeyBindingTokenTagged, KeyBindingTokenUnprotected},
    reexports::coset::{
        TaggedCborSerializable, {self},
    },
};
use signature::Signer;

pub mod error;
pub mod params;

pub trait Holder {
    type Error: std::error::Error + Send + Sync;

    type Signature;

    #[cfg(not(any(feature = "pem", feature = "der")))]
    type Signer: Signer<Self::Signature>;

    #[cfg(any(feature = "pem", feature = "der"))]
    type Signer: Signer<Self::Signature> + pkcs8::DecodePrivateKey;

    type IssuerProtectedClaims: CustomClaims;
    type IssuerUnprotectedClaims: CustomClaims;
    type IssuerPayloadClaims: CustomClaims;
    type KbtProtectedClaims: CustomClaims;
    type KbtUnprotectedClaims: CustomClaims;
    type KbtPayloadClaims: CustomClaims;
    type DisclosedClaims: CustomClaims;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm;
    fn hash_algorithm(&self) -> SelectiveDisclosureHashAlg;
    fn hash(&self, msg: &[u8]) -> Vec<u8>;

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
        params: CwtPresentationParams<Self::KbtProtectedClaims, Self::KbtUnprotectedClaims, Self::KbtPayloadClaims>,
    ) -> Result<
        KeyBindingTokenTagged<
            Self::IssuerProtectedClaims,
            Self::IssuerUnprotectedClaims,
            Self::IssuerPayloadClaims,
            Self::KbtProtectedClaims,
            Self::KbtUnprotectedClaims,
            Self::KbtPayloadClaims,
            Self::DisclosedClaims,
        >,
        SdCwtHolderError<Self::Error>,
    > {
        let mut sd_cwt_issued = SelectiveDisclosureIssuedTagged::from_cbor_bytes(sd_cwt_issued)?;

        // --- building the kbt ---
        // --- unprotected ---
        let unprotected = KeyBindingTokenUnprotected {
            claims: params.extra_kbt_unprotected,
        }
        .into();

        // --- redaction of claims ---
        // select the claims to disclose
        let sd_claims = match params.presentation {
            Presentation::Full => select_claims(sd_cwt_issued.0.sd_unprotected.sd_claims.try_into_value()?),
        };

        // then replace them in the issued sd-cwt
        sd_cwt_issued.0.sd_unprotected.sd_claims = sd_claims.into();

        // --- protected ---
        let alg = coset::Algorithm::Assigned(self.cwt_algorithm());
        let protected =
            KeyBindingTokenProtected::<Self::IssuerProtectedClaims, Self::IssuerUnprotectedClaims, Self::IssuerPayloadClaims, Self::KbtProtectedClaims, Self::DisclosedClaims> {
                alg: alg.into(),
                issuer_sd_cwt: sd_cwt_issued.into(),
                claims: params.extra_kbt_protected,
            }
            .try_into()
            .map_err(|_| SdCwtHolderError::ImplementationError("Failed mapping kbt protected to COSE header"))?;

        // --- payload ---
        let now = unix_timestamp(Some(params.leeway));
        let expiration = Some((now + params.expiry.as_secs()) as i64);
        let not_before = Some(now as i64);
        let issued_at = now as i64;

        let payload = KeyBindingTokenPayload {
            audience: params.audience.to_string(),
            expiration,
            not_before,
            issued_at,
            client_nonce: None,
            claims: params.extra_kbt_payload,
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
        Ok(KeyBindingTokenTagged::from_cbor_bytes(&sign1)?)
    }
}

// TODO: filter at some point either with json path or other
fn select_claims(claims: SaltedArray) -> SaltedArray {
    claims
}

pub fn unix_timestamp(leeway: Option<core::time::Duration>) -> u64 {
    now() - leeway.unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::{test_utils::Ed25519Holder, *};
    use crate::{
        IssueCwtParams, Issuer,
        issuer::{claims::CustomTokenClaims, test_utils::Ed25519IssuerClaims},
    };
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

        let disclosable_claims = CustomTokenClaims { name: "Alice Smith".into() };
        let issue_params = IssueCwtParams {
            protected_claims: None,
            unprotected_claims: None,
            payload_claims: None,
            disclosable_claims,
            subject: "mimi://example.com/u/alice.smith",
            identifier: "mimi://example.com/i/acme.io",
            key_location: "https://auth.acme.io/issuer.cwk",
            expiry: core::time::Duration::from_secs(90),
            leeway: core::time::Duration::from_secs(1),
            holder_confirmation_key: (&holder_signing_key.verifying_key()).try_into().unwrap(),
        };
        let sd_cwt = issuer.issue_cwt(&mut csprng, issue_params).unwrap().to_cbor_bytes().unwrap();

        let holder = Ed25519Holder::<CustomTokenClaims>::new(holder_signing_key);
        let presentation_params = CwtPresentationParams {
            presentation: Presentation::Full,
            audience: "mimi://example.com/r/alice-bob-group",
            expiry: core::time::Duration::from_secs(90 * 24 * 3600),
            leeway: core::time::Duration::from_secs(3600),
            extra_kbt_unprotected: None,
            extra_kbt_protected: None,
            extra_kbt_payload: None,
        };

        let mut sd_cwt_kbt = holder.new_presentation(&sd_cwt, presentation_params).unwrap();

        let sd_cwt_kbt_2 = sd_cwt_kbt.to_cbor_bytes().unwrap();
        let sd_cwt_kbt_2 = KeyBindingTokenTagged::from_cbor_bytes(&sd_cwt_kbt_2).unwrap();
        assert_eq!(sd_cwt_kbt, sd_cwt_kbt_2);

        let disclosable_claims = sd_cwt_kbt.0.walk_disclosed_claims().unwrap().collect::<Vec<_>>();
        assert_eq!(disclosable_claims.len(), 1);
        let is_alice = |sc: &SaltedClaim<ciborium::Value>| sc.name == ClaimName::Text("name".into()) && sc.value == cbor!("Alice Smith").unwrap();

        assert!(disclosable_claims.into_iter().any(|c| { matches!(c.unwrap(), Salted::Claim(sc) if is_alice(&sc)) }));
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
                    DisclosedClaims = NoClaims,
                    Error = std::convert::Infallible,
                    Signer = ed25519_dalek::SigningKey,
                    Signature = ed25519_dalek::Signature,
                >,
        >,
    ) {
    }
}

#[cfg(feature = "test-utils")]
pub mod test_utils {
    use esdicawt_spec::{CustomClaims, NoClaims, reexports::coset};

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    pub struct Ed25519Holder<DisclosedClaims: CustomClaims> {
        signing_key: ed25519_dalek::SigningKey,
        pub _marker: core::marker::PhantomData<DisclosedClaims>,
    }

    impl<DisclosedClaims: CustomClaims> super::Holder for Ed25519Holder<DisclosedClaims>
    where
        ed25519_dalek::SigningKey: signature::Signer<ed25519_dalek::Signature>,
    {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Signature = ed25519_dalek::Signature;

        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = DisclosedClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;
        type DisclosedClaims = DisclosedClaims;

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

        fn hash_algorithm(&self) -> esdicawt_spec::SelectiveDisclosureHashAlg {
            esdicawt_spec::SelectiveDisclosureHashAlg::Sha256
        }

        fn hash(&self, msg: &[u8]) -> Vec<u8> {
            use digest::Digest as _;
            sha2::Sha256::digest(msg).to_vec()
        }
    }
}
