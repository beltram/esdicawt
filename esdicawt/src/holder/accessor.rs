use crate::{SdCwtVerifierError, SdCwtVerifierResult, verifier::walk::walk_payload};
use ciborium::{Value, value::Integer};
use esdicawt_spec::{CWT_CLAIM_KEY_CONFIRMATION, CustomClaims, CwtAny, Select, issuance::SdInnerPayload, key_binding::KbtCwt};
use std::{collections::HashMap, convert::Infallible};

pub trait ClaimSetExt {
    type Payload: Select;

    /// Given a SD-KBT, either verified or not, computes the claimset.
    /// The signature is not verified here (in order to be faster than the verified version) so use at your own risk !
    fn claimset_unchecked(&mut self) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible>;
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

    fn claimset_unchecked(&mut self) -> SdCwtVerifierResult<Option<Self::Payload>, Infallible> {
        let kbt_protected = self.protected.to_value_mut()?;
        let sd_cwt = kbt_protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let mut payload = sd_cwt_payload.to_cbor_value()?;
        if let Some(disclosures) = sd_cwt.0.disclosures_mut() {
            let disclosures_size = disclosures.len();

            // compute the hash of all disclosures
            let mut disclosures = disclosures
                .iter_mut()
                .map(|d| match d {
                    Ok(salted) => {
                        let bytes = salted.to_cbor_bytes()?;
                        let digest = Hasher::digest(&bytes[..]).to_vec();
                        SdCwtVerifierResult::Ok((digest, salted))
                    }
                    Err(e) => Err(e.into()),
                })
                .collect::<Result<HashMap<_, _>, _>>()?;

            if disclosures.len() != disclosures_size {
                return Err(SdCwtVerifierError::DisclosureHashCollision);
            }

            walk_payload(&mut payload, &mut disclosures)?;
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
