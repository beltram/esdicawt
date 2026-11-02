use crate::{
    PresentArgs,
    keys::{AnySignature, AnySigningKey, AnyVerifyingKey},
    token::{Sign1, decode, disclosure_salt, issuer_keyset, read_stdin, time_verification, unsupported, write_stdout},
};
use ciborium::Value;
use esdicawt::{
    Holder, HolderParams, HolderValidationParams, KbtIatOrCti, Presentation, coset,
    spec::{NoClaims, blinded_claims::SaltedArray},
};
use std::{collections::HashSet, path::Path, time::Duration};

pub fn present(args: PresentArgs) -> eyre::Result<()> {
    if args.encrypt_list.is_some() {
        return Err(unsupported(
            "--encrypt_list: AEAD encrypted disclosures (sd_aead_encrypted_claims, 171) are not implemented",
        ));
    }
    let sd_cwt = read_stdin()?;
    let sign1 = Sign1::from_bytes(&sd_cwt)?;
    let keyset = issuer_keyset(args.issuer.as_deref(), args.issuer_key, &sign1)?;
    let holder = CliHolder::new(AnySigningKey::from_pem_file(&args.holder_priv)?);

    let presentation = if args.disclose_all {
        Presentation::Full
    } else if let Some(list) = &args.disclosure_list {
        let salts = read_salts(list)?;
        let available = sign1.sd_claims().iter().map(|d| disclosure_salt(d)).collect::<eyre::Result<HashSet<_>>>()?;
        let missing = salts.iter().filter(|s| !available.contains(*s)).map(hex::encode).collect::<Vec<_>>();
        if !missing.is_empty() {
            eyre::bail!("no disclosure with salt {missing:?}");
        }
        Presentation::Custom(Box::new(move |mut issued: SaltedArray| {
            issued.retain(|d| d.to_value().is_ok_and(|d| salts.contains(&d.salt().0[..])));
            issued
        }))
    } else {
        Presentation::None
    };

    let time_verification = time_verification(args.time);
    let artificial_time = args.time.map(Duration::from_secs);
    let params = HolderValidationParams {
        expected_subject: None,
        expected_issuer: None,
        expected_audience: None,
        expected_cnonce: None,
        leeway: Duration::ZERO,
        time_verification,
        artificial_time,
    };
    let sd_cwt = holder.verify_sd_cwt(&sd_cwt, params, &keyset)?;

    let params = HolderParams {
        presentation,
        audience: &args.audience,
        cnonce: None,
        iat_or_cti: KbtIatOrCti::Iat {
            expiry: None,
            with_not_before: false,
            cti: None,
        },
        artificial_time,
        time_verification,
        leeway: Duration::ZERO,
        extra_kbt_protected: None,
        extra_kbt_unprotected: None,
        extra_kbt_payload: None,
    };
    let kbt = holder.new_presentation_raw(sd_cwt, params)?;
    write_stdout(&kbt)
}

/// A CBOR array of salts
fn read_salts(path: &Path) -> eyre::Result<HashSet<Vec<u8>>> {
    let bytes = std::fs::read(path).map_err(|e| eyre::eyre!("cannot read '{}': {e}", path.display()))?;
    match decode(&bytes)? {
        Value::Array(salts) => salts
            .into_iter()
            .map(|s| s.into_bytes().map_err(|_| eyre::eyre!("'{}' must only contain byte strings", path.display())))
            .collect(),
        _ => eyre::bail!("'{}' is not a CBOR array", path.display()),
    }
}

pub struct CliHolder {
    signing_key: AnySigningKey,
    verifying_key: AnyVerifyingKey,
}

impl Holder for CliHolder {
    type Error = std::convert::Infallible;
    type Hasher = sha2::Sha256;
    type Signer = AnySigningKey;
    type Signature = AnySignature;
    type Verifier = AnyVerifyingKey;

    type IssuerPayloadClaims = Value;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
    type KbtPayloadClaims = NoClaims;

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        self.signing_key.algorithm()
    }

    fn new(signing_key: Self::Signer) -> Self {
        Self {
            verifying_key: signature::Keypair::verifying_key(&signing_key),
            signing_key,
        }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn verifier(&self) -> &Self::Verifier {
        &self.verifying_key
    }
}
