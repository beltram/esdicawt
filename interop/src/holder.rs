use crate::KeyFetch;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use esdicawt::{
    Holder, HolderParams, HolderValidationParams, Presentation,
    cose_key::keyset::CoseKeySet,
    coset,
    spec::{NoClaims, Value},
};
use std::{io::Read, path::PathBuf, time::Duration};

pub fn present(
    holder_priv: PathBuf,
    issuer_pub: PathBuf,
    _issuer_key: KeyFetch,
    _disclosure_list: Option<PathBuf>,
    disclosure_all: Option<bool>,
    time: Option<u64>,
) -> eyre::Result<()> {
    let mut sd_cwt = vec![];
    std::io::stdin().read_to_end(&mut sd_cwt)?;

    let signing_key = ed25519_dalek::SigningKey::read_pkcs8_pem_file(holder_priv)?;
    let issuer_pub = ed25519_dalek::VerifyingKey::read_public_key_pem_file(issuer_pub)?;
    let holder = Ed25519Holder {
        verifying_key: signing_key.verifying_key(),
        signing_key,
    };

    let params = HolderValidationParams {
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_cnonce: None,
        leeway: Default::default(),
        time_verification: Default::default(),
        artificial_time: None,
    };
    let cks = CoseKeySet::builder().with(&issuer_pub)?.build();
    let sd_cwt_verified = holder.verify_sd_cwt(&sd_cwt, params, &cks)?;

    let presentation = match disclosure_all {
        Some(true) => Presentation::Full,
        _ => Presentation::None,
    };
    let params = HolderParams {
        presentation,
        audience: "",
        cnonce: None,
        expiry: None,
        with_not_before: false,
        artificial_time: time.map(Duration::from_secs),
        time_verification: Default::default(),
        leeway: Default::default(),
        extra_kbt_protected: None,
        extra_kbt_unprotected: None,
        extra_kbt_payload: None,
    };
    holder.new_presentation(sd_cwt_verified, params)?;
    Ok(())
}

pub struct Ed25519Holder {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Holder for Ed25519Holder {
    type Error = std::convert::Infallible;
    type Signer = ed25519_dalek::SigningKey;

    type Signature = ed25519_dalek::Signature;
    type Verifier = ed25519_dalek::VerifyingKey;

    type Hasher = sha2::Sha256;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type IssuerPayloadClaims = Value;
    type KbtUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;

    type KbtPayloadClaims = NoClaims;

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: signing_key.verifying_key(),
            signing_key,
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
