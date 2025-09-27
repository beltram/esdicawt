use esdicawt::{Holder, Issuer, Verifier};
use esdicawt_spec::{CustomClaims, EsdicawtSpecError, NoClaims, SdHashAlg, Select, reexports::coset::iana::Algorithm};

pub mod ed25519 {
    use super::*;

    pub struct Ed25519Issuer<T: Select, H: digest::Digest + Clone> {
        signing_key: ed25519_dalek::SigningKey,
        _marker: core::marker::PhantomData<(T, H)>,
    }

    impl<T: Select, H: digest::Digest + Clone> Issuer for Ed25519Issuer<T, H> {
        type Error = core::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = H;
        type Signature = ed25519_dalek::Signature;

        type PayloadClaims = T;
        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;

        fn new(signing_key: Self::Signer) -> Self
        where
            Self: Sized,
        {
            Self {
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }
    }

    pub struct Ed25519Holder<T: Select, H: digest::Digest + Clone> {
        signing_key: ed25519_dalek::SigningKey,
        pub verifying_key: ed25519_dalek::VerifyingKey,
        _marker: core::marker::PhantomData<(T, H)>,
    }

    impl<T: Select, H: digest::Digest + Clone> Holder for Ed25519Holder<T, H> {
        type Error = EsdicawtSpecError;
        type Hasher = H;
        type Signer = ed25519_dalek::SigningKey;

        type Signature = ed25519_dalek::Signature;
        type Verifier = ed25519_dalek::VerifyingKey;

        type IssuerPayloadClaims = T;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;

        fn cwt_algorithm(&self) -> Algorithm {
            Algorithm::EdDSA
        }

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                verifying_key: *signing_key.as_ref(),
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn verifier(&self) -> &Self::Verifier {
            &self.verifying_key
        }
    }

    pub struct Ed25519Verifier<T: Select, U: CustomClaims = NoClaims> {
        pub _marker: core::marker::PhantomData<(T, U)>,
    }

    #[allow(clippy::new_without_default)]
    impl<T: Select, U: CustomClaims> Ed25519Verifier<T, U> {
        pub fn new() -> Self {
            Self { _marker: Default::default() }
        }
    }

    impl<T: Select, U: CustomClaims> Verifier for Ed25519Verifier<T, U> {
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
}

pub mod es_256 {
    use super::*;

    pub struct P256Holder<T: Select> {
        signing_key: p256::ecdsa::SigningKey,
        verifying_key: p256::ecdsa::VerifyingKey,
        _marker: core::marker::PhantomData<T>,
    }

    impl<T: Select> Holder for P256Holder<T> {
        type Error = EsdicawtSpecError;
        type Hasher = sha2::Sha256;
        type Signer = p256::ecdsa::SigningKey;

        type Signature = p256::ecdsa::Signature;
        type Verifier = p256::ecdsa::VerifyingKey;

        type IssuerPayloadClaims = T;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;

        fn cwt_algorithm(&self) -> Algorithm {
            Algorithm::ES256
        }

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                verifying_key: *signing_key.as_ref(),
                signing_key,
                _marker: Default::default(),
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn verifier(&self) -> &Self::Verifier {
            &self.verifying_key
        }
    }
}
