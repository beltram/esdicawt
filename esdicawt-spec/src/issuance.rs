use crate::{CustomClaims, CwtAny, NoClaims, SdHashAlg, Select, alg::Algorithm, blinded_claims::SaltedArray, inlined_cbor::InlinedCbor, redacted_claims::RedactedClaimKeys};

mod accessors;
mod sd_issued_codec;
mod sd_payload_codec;
mod sd_protected_codec;
mod sd_unprotected_codec;

#[derive(Debug, Clone)]
pub struct SdCwtIssued<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims> {
    pub protected: InlinedCbor<SdProtected<ProtectedClaims>>,
    pub sd_unprotected: SdUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<SdPayload<PayloadClaims>>,
    pub signature: serde_bytes::ByteBuf,
    _marker: core::marker::PhantomData<Hasher>,
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> PartialEq
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn eq(&self, other: &Self) -> bool {
        self.protected.eq(&other.protected) && self.sd_unprotected.eq(&other.sd_unprotected) && self.payload.eq(&other.payload) && self.signature.eq(&other.signature)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdProtected<Extra: CustomClaims> {
    pub alg: Algorithm,
    /// Optional, see [Self::sd_alg] for the effective hash algorithm
    pub sd_alg: Option<SdHashAlg>,
    pub extra: Option<Extra>,
}

impl<Extra: CustomClaims> SdProtected<Extra> {
    /// Hash algorithm of the Salted Disclosed Claims, SHA-256 when 'sd_alg' is absent
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-sd-cwt-issuance
    pub fn sd_alg(&self) -> SdHashAlg {
        self.sd_alg.unwrap_or(SdHashAlg::Sha256)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdUnprotected<Extra: CustomClaims> {
    pub sd_claims: Option<SaltedArray>,
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdPayload<Extra: CwtAny> {
    pub cnf: cose_key::confirmation::KeyConfirmation,
    pub redacted_claim_keys: Option<RedactedClaimKeys>,
    pub inner: SdInnerPayload<Extra>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdInnerPayload<Extra: CwtAny> {
    pub issuer: String,
    pub subject: Option<String>,
    pub audience: Option<String>,
    pub expiration: Option<i64>,
    pub not_before: Option<i64>,
    pub issued_at: Option<i64>,
    pub cti: Option<serde_bytes::ByteBuf>,
    pub cnonce: Option<serde_bytes::ByteBuf>,
    #[cfg(feature = "status")]
    pub status: status_list::StatusClaim,
    pub extra: Option<Extra>,
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims>
    SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    pub fn disclosures(&self) -> Option<&SaltedArray> {
        self.sd_unprotected.sd_claims.as_ref()
    }

    pub fn take_disclosures(self) -> Option<SaltedArray> {
        self.sd_unprotected.sd_claims
    }

    pub fn disclosures_mut(&mut self) -> Option<&mut SaltedArray> {
        self.sd_unprotected.sd_claims.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn should_be_comparable<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims>(
        a: SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
        b: SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
    ) -> bool {
        a == b
    }
}
