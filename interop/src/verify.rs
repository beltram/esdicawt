use crate::{
    VerifyArgs,
    keys::{AnySignature, AnyVerifyingKey},
    token::{Sign1, encode, issuer_keyset, label_is, map_get, read_stdin, time_verification, unsupported, write_stdout},
};
use ciborium::Value;
use esdicawt::{
    SdCwtVerifierError, Verifier, VerifierParams,
    spec::{
        CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION, CWT_CLAIM_NOT_BEFORE,
        CWT_CLAIM_SUBJECT, NoClaims,
    },
};
use std::time::Duration;

pub fn verify(args: VerifyArgs) -> eyre::Result<()> {
    write_stdout(&verify_kbt(&read_stdin()?, &args)?)
}

/// Verifies a SD-KBT and returns the CBOR of the validated claims set
pub fn verify_kbt(kbt: &[u8], args: &VerifyArgs) -> eyre::Result<Vec<u8>> {
    let sd_cwt = Sign1::from_bytes(kbt)?.kcwt()?;
    let keyset = issuer_keyset(args.issuer.as_deref(), args.issuer_key, &sd_cwt)?;

    let encrypted = sd_cwt.aead_encrypted_claims();
    if encrypted > 0 {
        if !args.aead_key.is_empty() {
            return Err(unsupported(format!(
                "--aead-key: cannot decrypt the {encrypted} AEAD encrypted disclosure(s) (sd_aead_encrypted_claims, 171), not implemented"
            )));
        }
        eprintln!("{encrypted} AEAD encrypted disclosure(s) left undisclosed");
    }

    let audience = args.audience.as_deref().map(|a| [a]);
    let time_verification = time_verification(args.time);
    let params = |expected_subject| VerifierParams {
        expected_subject,
        expected_issuer: None,
        expected_audience: None,
        expected_kbt_audience: audience.as_ref().map(<[&str; 1]>::as_slice).unwrap_or_default(),
        expected_cnonce: None,
        sd_cwt_leeway: Duration::ZERO,
        sd_kbt_leeway: Duration::ZERO,
        sd_cwt_time_verification: time_verification,
        sd_kbt_time_verification: time_verification,
        artificial_time: args.time.and_then(|t| i64::try_from(t).ok()),
    };

    // esdicawt always verifies 'sub' (which can be redacted) against an expected one, which the harness does not give.
    // So the subject is taken from the payload, or from the error when it is redacted
    let plain_subject = match map_get(&sd_cwt.payload, CWT_CLAIM_SUBJECT) {
        Some(Value::Text(s)) => s.clone(),
        _ => String::new(),
    };
    let (verified, subject) = match CliVerifier.verify_sd_kbt(kbt, &params(&plain_subject), None, &keyset) {
        Ok(verified) => (verified, plain_subject),
        Err(SdCwtVerifierError::SubMismatch { actual, .. }) if !actual.is_empty() => (CliVerifier.verify_sd_kbt(kbt, &params(&actual), None, &keyset)?, actual),
        Err(e) => return Err(e.into()),
    };

    // the validated claims set: the standard claims, which esdicawt keeps aside, and the disclosed claims
    const STANDARD_CLAIMS: [i64; 8] = [
        CWT_CLAIM_ISSUER,
        CWT_CLAIM_AUDIENCE,
        CWT_CLAIM_EXPIRES_AT,
        CWT_CLAIM_NOT_BEFORE,
        CWT_CLAIM_ISSUED_AT,
        CWT_CLAIM_CTI,
        CWT_CLAIM_KEY_CONFIRMATION,
        CWT_CLAIM_CNONCE,
    ];
    let mut claims = vec![(Value::from(CWT_CLAIM_SUBJECT), Value::Text(subject))];
    claims.extend(sd_cwt.payload.iter().filter(|(k, _)| STANDARD_CLAIMS.iter().any(|&l| label_is(k, l))).cloned());
    match verified.claimset {
        Some(Value::Map(disclosed)) => {
            for (k, v) in disclosed {
                if !claims.iter().any(|(c, _)| *c == k) {
                    claims.push((k, v));
                }
            }
        }
        Some(Value::Null) | None => {}
        Some(other) => eyre::bail!("unexpected claims set {other:?}"),
    }
    encode(&Value::Map(claims))
}

#[derive(Debug, Clone, Copy)]
pub struct CliVerifier;

impl Verifier for CliVerifier {
    type Error = std::convert::Infallible;
    type HolderSignature = AnySignature;
    type HolderVerifier = AnyVerifyingKey;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type IssuerPayloadClaims = Value;
    type KbtPayloadClaims = NoClaims;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
}

#[cfg(test)]
mod tests {
    //! A SD-KBT carrying AEAD encrypted disclosures, as other Holders produce for the `aead_first_disclosure` test case:
    //! the draft's issued SD-CWT with disclosure 501 moved from 'sd_claims' to 'sd_aead_encrypted_claims'
    use super::*;
    use crate::{
        keys::AnySigningKey,
        token::{HEADER_KCWT, HEADER_SD_AEAD_ENCRYPTED_CLAIMS, HEADER_SD_CLAIMS, decode},
    };

    const CASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../draft-ietf-spice-sd-cwt/interop/test_cases/aead_first_disclosure");

    fn kbt_with_aead_claims() -> Vec<u8> {
        let issued = std::fs::read(format!("{CASE}/issued.cbor")).unwrap();
        let Value::Tag(18, sd_cwt) = decode(&issued).unwrap() else { unreachable!() };
        let Value::Array(mut sd_cwt) = *sd_cwt else { unreachable!() };
        let Some(Value::Map(unprotected)) = sd_cwt.get_mut(1) else { unreachable!() };
        for (k, v) in unprotected.iter_mut() {
            if label_is(k, HEADER_SD_CLAIMS) {
                let Value::Array(disclosures) = v else { unreachable!() };
                disclosures.retain(|d| !matches!(decode(d.as_bytes().unwrap()).unwrap(), Value::Array(a) if a.last() == Some(&Value::from(501))));
            }
        }
        let aead_claims = decode(&std::fs::read(format!("{CASE}/expected_aead_claims.cbor")).unwrap()).unwrap();
        unprotected.push((HEADER_SD_AEAD_ENCRYPTED_CLAIMS.into(), aead_claims));

        let protected = encode(&Value::Map(vec![
            (1.into(), (-7).into()),
            (16.into(), 294.into()),
            (HEADER_KCWT.into(), Value::Tag(18, Box::new(Value::Array(sd_cwt)))),
        ]))
        .unwrap();
        let payload = encode(&Value::Map(vec![(3.into(), "https://verifier.example/app".into()), (6.into(), 1725244237.into())])).unwrap();
        let tbs = encode(&Value::Array(vec![
            "Signature1".into(),
            Value::Bytes(protected.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(payload.clone()),
        ]))
        .unwrap();
        let holder = AnySigningKey::from_pem(&std::fs::read_to_string(format!("{CASE}/holder_priv.pem")).unwrap()).unwrap();
        let signature: Vec<u8> = signature::Signer::sign(&holder, &tbs).into();
        let kbt = Value::Array(vec![Value::Bytes(protected), Value::Map(vec![]), Value::Bytes(payload), Value::Bytes(signature)]);
        encode(&Value::Tag(18, Box::new(kbt))).unwrap()
    }

    fn args(aead_key: Option<&str>) -> VerifyArgs {
        VerifyArgs {
            issuer: Some(format!("{CASE}/issuer_pub.pem").into()),
            issuer_key: None,
            audience: None,
            aead_key: aead_key.map(|k| format!("{CASE}/{k}").into()).into_iter().collect(),
            time: None,
        }
    }

    #[test]
    fn should_verify_and_withhold_aead_claims_without_a_key() {
        let claims = decode(&verify_kbt(&kbt_with_aead_claims(), &args(None)).unwrap()).unwrap().into_map().unwrap();
        assert!(map_get(&claims, 501).is_none());
        assert!(map_get(&claims, 500).is_some());
    }

    #[test]
    fn should_not_pretend_to_decrypt_aead_claims() {
        for key in ["aead_key.hex", "wrong_aead_key.hex"] {
            let err = verify_kbt(&kbt_with_aead_claims(), &args(Some(key))).unwrap_err();
            assert!(err.downcast_ref::<crate::token::Unsupported>().is_some(), "{err}");
        }
    }
}
