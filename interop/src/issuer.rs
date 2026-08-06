use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePublicKey};
use esdicawt::cose_key::confirmation::KeyConfirmation;
use esdicawt::spec::{CwtAny, cbor};
use esdicawt::{
    Issuer, IssuerParams, coset,
    spec::{EsdicawtSpecError, NoClaims, SdHashAlg, Value},
};
use std::io::Read;
use std::{io::Write, path::PathBuf, time::Duration};

pub fn issue(issuer_priv: PathBuf, _nonces: Option<PathBuf>, time: Option<u64>) -> eyre::Result<()> {
    let mut cbor_value = vec![];
    std::io::stdin().read_to_end(&mut cbor_value)?;
    let payload = Value::from_cbor_bytes(&cbor_value).unwrap();

    let signing_key = ed25519_dalek::SigningKey::read_pkcs8_pem_file(issuer_priv)?;
    let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
    let issuer = Ed25519Issuer { signing_key };
    let params = IssuerParams {
        protected_claims: None,
        unprotected_claims: None,
        payload: Some(payload),
        issuer: "",
        subject: None,
        audience: None,
        expiry: None,
        with_not_before: false,
        with_issued_at: false,
        cti: None,
        cnonce: None,
        artificial_time: time.map(Duration::from_secs),
        leeway: Default::default(),
        key_location: "",
        holder_confirmation_key: (&holder_signing_key).try_into()?,
    };
    let sd_cwt = issuer.issue_raw_cwt(&mut rand::thread_rng(), params)?;
    std::io::stdout().write_all(&sd_cwt)?;
    Ok(())
}

pub struct Ed25519Issuer {
    signing_key: ed25519_dalek::SigningKey,
}

impl Issuer for Ed25519Issuer {
    type Error = EsdicawtSpecError;
    type Hasher = sha2::Sha256;
    type Signer = ed25519_dalek::SigningKey;
    type Signature = ed25519_dalek::Signature;

    type ProtectedClaims = NoClaims;
    type UnprotectedClaims = NoClaims;
    type PayloadClaims = Value;

    fn new(signing_key: Self::Signer) -> Self {
        Self { signing_key }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::EdDSA
    }

    fn hash_algorithm(&self) -> SdHashAlg {
        SdHashAlg::Sha256
    }
}

#[test]
fn generate_inputs() {
    use ed25519_dalek::pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding};

    for label in ["issuer", "holder"] {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        std::fs::write(format!("./in/{label}-priv.pem"), key.to_pkcs8_pem(LineEnding::LF).unwrap().as_str()).unwrap();
        std::fs::write(format!("./in/{label}-pub.pem"), key.verifying_key().to_public_key_pem(LineEnding::LF).unwrap().as_str()).unwrap();
        let cnf: KeyConfirmation = (&key.verifying_key()).try_into().unwrap();
        std::fs::write(format!("./in/{label}-cnf.txt"), hex::encode(cnf.to_cbor_bytes().unwrap())).unwrap();
    }
    let value = cbor!({
        "code" => 415,
        "message" => null,
        "continue" => false,
        "extra" => { "numbers" => [8.2341e+4, 0.251425] },
    })
    .unwrap();
    std::fs::write("./in/input.cbor", value.to_cbor_bytes().unwrap()).unwrap();
}
