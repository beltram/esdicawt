use crate::spec::reexports::coset;
use coset::{CoseSign1, iana, iana::EnumI64};

/// The `Sig_structure` signed in a COSE_Sign1 (see RFC 9052 section 4.4) built from the raw bytes of its protected header
/// and payload, to avoid having to parse the whole COSE_Sign1
pub fn cose_sign1_tbs(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, SignatureVerifierError> {
    use serde_bytes::Bytes;

    const CONTEXT: &str = "Signature1";
    let external_aad = Bytes::new(&[]);
    Ok(seabored::serde::to_vec(&(CONTEXT, Bytes::new(protected), external_aad, Bytes::new(payload)))?)
}

pub fn validate_cose_sign1_signature(sign1: &CoseSign1, cks: &cose_key::keyset::CoseKeySet) -> Result<(), SignatureVerifierError> {
    validate_signature(&iana_alg(sign1.protected.header.alg.as_ref())?, &sign1.tbs_data(&[]), &sign1.signature, cks)
}

pub fn iana_alg(alg: Option<&coset::Algorithm>) -> Result<iana::Algorithm, SignatureVerifierError> {
    Ok(match alg.ok_or(SignatureVerifierError::InvalidCwt)? {
        coset::Algorithm::Assigned(i) => iana::Algorithm::from_i64(i.to_i64()).ok_or(SignatureVerifierError::UnsupportedAlgorithm)?,
        _ => return Err(SignatureVerifierError::UnsupportedAlgorithm),
    })
}

pub fn validate_signature(
    alg: &iana::Algorithm,
    #[allow(unused_variables)] tbs: &[u8],
    #[allow(unused_variables)] signature: &[u8],
    cks: &cose_key::keyset::CoseKeySet,
) -> Result<(), SignatureVerifierError> {
    for key in cks.find_keys(alg) {
        match key.crv() {
            #[cfg(feature = "ed25519")]
            Some(iana::EllipticCurve::Ed25519) => {
                use signature::Verifier as _;
                let signature = ed25519_dalek::Signature::from_slice(signature)?;
                let verifier = ed25519_dalek::VerifyingKey::try_from(key)?;
                return Ok(verifier.verify(tbs, &signature)?);
            }
            #[cfg(feature = "p256")]
            Some(iana::EllipticCurve::P_256) => {
                use signature::Verifier as _;
                let signature = p256::ecdsa::Signature::from_slice(signature)?;
                let verifier = p256::ecdsa::VerifyingKey::try_from(key)?;
                return Ok(verifier.verify(tbs, &signature)?);
            }
            #[cfg(feature = "p384")]
            Some(iana::EllipticCurve::P_384) => {
                use signature::Verifier as _;
                let signature = p384::ecdsa::Signature::from_slice(signature)?;
                let verifier = p384::ecdsa::VerifyingKey::try_from(key)?;
                return Ok(verifier.verify(tbs, &signature)?);
            }
            _ => {}
        }
    }
    Err(SignatureVerifierError::NoSigner)
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureVerifierError {
    #[error("This algorithm is not supported")]
    UnsupportedAlgorithm,
    #[error("Invalid CWT")]
    InvalidCwt,
    #[error("No signer found for this CWT in this CoseKeySet")]
    NoSigner,
    #[error(transparent)]
    CoseKeyError(#[from] cose_key::CoseKeyError),
    #[error("Signature verification error: {0}")]
    SignatureError(#[from] signature::Error),
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    SerializationError(#[from] seabored::error::SeaboredSerError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use coset::{CborSerializable as _, CoseSign1Builder, HeaderBuilder};

    #[test]
    fn tbs_should_match_coset() {
        for payload_len in [0usize, 23, 24, 256, 0x1_0000] {
            let protected = HeaderBuilder::new().algorithm(iana::Algorithm::EdDSA).key_id(vec![1; 64]).build();
            let sign1 = CoseSign1Builder::new().protected(protected).payload(vec![0xAB; payload_len]).signature(vec![0; 64]).build();
            // parsing keeps the raw bytes of the protected header, like when verifying
            let sign1 = CoseSign1::from_slice(&sign1.to_vec().unwrap()).unwrap();

            let protected = sign1.protected.original_data.as_deref().unwrap();
            let payload = sign1.payload.as_deref().unwrap();
            assert_eq!(cose_sign1_tbs(protected, payload).unwrap(), sign1.tbs_data(&[]), "payload length {payload_len}");
        }
    }
}
