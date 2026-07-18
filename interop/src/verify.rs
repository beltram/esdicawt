use crate::KeyFetch;
use ed25519_dalek::pkcs8::DecodePublicKey;
use esdicawt::{
    Verifier, VerifierParams,
    cose_key::keyset::CoseKeySet,
    spec::{NoClaims, Value},
};
use std::{io::Read, path::PathBuf};

pub fn verify(issuer_pub: PathBuf, _issuer_key: KeyFetch, _audience: Option<String>, time: Option<u64>) -> eyre::Result<()> {
    let mut sd_kbt = vec![];
    std::io::stdin().read_to_end(&mut sd_kbt)?;

    let issuer_pub = ed25519_dalek::VerifyingKey::read_public_key_pem_file(issuer_pub)?;
    let cks = CoseKeySet::builder().with(&issuer_pub)?.build();
    let params = VerifierParams {
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
    Ed25519Verifier.verify_sd_kbt(&sd_kbt, params, None, &cks)?;
    Ok(())
}

#[derive(Copy, Clone, Debug)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    type Error = std::convert::Infallible;
    type HolderSignature = ed25519_dalek::Signature;
    type HolderVerifier = ed25519_dalek::VerifyingKey;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type IssuerPayloadClaims = Value;
    type KbtPayloadClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
}
