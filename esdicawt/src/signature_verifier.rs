use crate::{
    CoseKeyError,
    spec::reexports::coset::{Algorithm, CoseSign1, iana, iana::EnumI64},
};

pub fn validate_signature(cose_sign1_sd_cwt: &CoseSign1, keyset: &cose_key_set::CoseKeySet) -> Result<(), SignatureVerifierError> {
    let alg = cose_sign1_sd_cwt.protected.header.alg.as_ref().ok_or(SignatureVerifierError::InvalidCwt)?;
    let alg = match alg {
        Algorithm::Assigned(i) => iana::Algorithm::from_i64(i.to_i64()).ok_or(SignatureVerifierError::UnsupportedAlgorithm)?,
        _ => return Err(SignatureVerifierError::UnsupportedAlgorithm),
    };

    cose_sign1_sd_cwt.verify_signature(&[], |#[allow(unused_variables)] signature, #[allow(unused_variables)] raw_data| {
        for key in keyset.find_keys(&alg) {
            match key.crv() {
                #[cfg(feature = "ed25519")]
                Some(iana::EllipticCurve::Ed25519) => {
                    use signature::Verifier as _;
                    let signature = ed25519_dalek::Signature::from_slice(signature)?;
                    let verifier = ed25519_dalek::VerifyingKey::try_from(key)?;
                    return Ok(verifier.verify(raw_data, &signature)?);
                }
                #[cfg(feature = "p256")]
                Some(iana::EllipticCurve::P_256) => {
                    use signature::Verifier as _;
                    let signature = p256::ecdsa::Signature::from_slice(signature)?;
                    let verifier = p256::ecdsa::VerifyingKey::try_from(key)?;
                    return Ok(verifier.verify(raw_data, &signature)?);
                }
                #[cfg(feature = "p384")]
                Some(iana::EllipticCurve::P_384) => {
                    use signature::Verifier as _;
                    let signature = p384::ecdsa::Signature::from_slice(signature)?;
                    let verifier = p384::ecdsa::VerifyingKey::try_from(key)?;
                    return Ok(verifier.verify(raw_data, &signature)?);
                }
                _ => {}
            }
        }
        Err(SignatureVerifierError::NoSigner)
    })
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureVerifierError {
    #[error("This algorithm is not supported")]
    UnsupportedAlgorithm,
    #[error("Invalid CWT")]
    InvalidCwt,
    #[error("No signer found for this SD-CWT in this KeySet")]
    NoSigner,
    #[error(transparent)]
    CoseKeyError(#[from] CoseKeyError),
    #[error("Signature verification error: {0}")]
    SignatureError(#[from] signature::Error),
}
