use crate::{SdCwtVerifierError, SdCwtVerifierResult, verifier::walk::walk_payload};
use ciborium::{Value, value::Integer};
use digest::DynDigest;
use esdicawt_spec::{CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, Select, issuance::SdInnerPayload, key_binding::KbtCwt};
use std::convert::Infallible;

pub trait ClaimSetExt {
    type Payload: Select;

    /// Given a SD-KBT, either verified or not, computes the claimset.
    /// The signature is not verified here (in order to be faster than the verified version) so use at your own risk !
    fn claimset_unchecked(&mut self) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible>;
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + digest::FixedOutputReset + Clone + 'static,
    PayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
> ClaimSetExt for KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    type Payload = IssuerPayloadClaims;

    fn claimset_unchecked(&mut self) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible> {
        let mut sd_cwt = self.generic_sd_cwt()?;
        let mut payload = sd_cwt.payload.upcast_value()?;
        if let Some(disclosures) = sd_cwt.disclosures_mut() {
            let disclosures_size = disclosures.len();

            // compute the hash of all disclosures
            let mut disclosures = disclosures.to_verify()?;

            if disclosures.len() != disclosures_size {
                return Err(SdCwtVerifierError::DisclosureHashCollision);
            }

            walk_payload(Hasher::new().box_clone(), &mut payload, &mut disclosures)?;
        }
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
