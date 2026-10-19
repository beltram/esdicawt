use crate::{
    SdCwtVerifierError, SdCwtVerifierResult,
    spec::{CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, SdHashAlg, Select, blinded_claims::SaltedArray, issuance::SdInnerPayload, key_binding::KbtCwt},
    verifier::walk::walk_payload,
};
use ciborium::{Value, value::Integer};
use std::{convert::Infallible, rc::Rc};

pub trait ClaimSetExt {
    type Payload: Select;

    /// Given a SD-KBT, either verified or not, computes the claimset. `digest` provides the hasher of the 'sd_alg' of the
    /// SD-CWT, `None` when not supported.
    /// The signature is not verified here (in order to be faster than the verified version) so use at your own risk !
    fn claimset_unchecked_with(&self, digest: impl Fn(SdHashAlg) -> Option<Rc<dyn digest::DynDigest>>) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible>;

    /// Same as [Self::claimset_unchecked_with] with the hashers enabled by the features
    #[cfg(any(feature = "ed25519", feature = "p256", feature = "p384"))]
    fn claimset_unchecked(&self) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible> {
        self.claimset_unchecked_with(crate::default_digest)
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    PayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
> ClaimSetExt for KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    type Payload = IssuerPayloadClaims;

    fn claimset_unchecked_with(&self, digest: impl Fn(SdHashAlg) -> Option<Rc<dyn digest::DynDigest>>) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible> {
        let sd_cwt = self.generic_sd_cwt()?;
        let mut payload = sd_cwt.payload.upcast_value()?;
        // an absent 'sd_claims' is equivalent to no disclosure: undisclosed redacted claims still have to be removed
        let no_disclosures = SaltedArray::default();
        let disclosures = sd_cwt.disclosures().unwrap_or(&no_disclosures);
        // compute the hash of all disclosures with the 'sd_alg' of the SD-CWT
        let sd_alg = sd_cwt.protected.to_value()?.sd_alg();
        let hasher = digest(sd_alg).ok_or(SdCwtVerifierError::HasherNotFound(sd_alg))?;
        let mut disclosures = disclosures.digested_detached_hasher(&hasher)?;
        walk_payload(hasher, &mut payload, &mut disclosures)?;
        // puncture the 'cnf' claim before deserialization
        if let Some(map) = payload.as_map_mut() {
            map.retain(|(k, _)| !matches!(k, Value::Integer(i) if *i == Integer::from(CWT_CLAIM_KEY_CONFIRMATION)));
        }

        // TODO: this might fail if `Self::IssuerPayloadClaims` does not support unknown claims (serde flatten etc..)
        let sd_cwt_payload = payload.deserialized::<SdInnerPayload<Self::Payload>>()?;
        let claimset = sd_cwt_payload.extra;
        Ok(claimset)
    }
}
