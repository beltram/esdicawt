use crate::{CustomClaims, CwtAny, NoClaims, SdHashAlg, Select, alg::Algorithm, blinded_claims::SaltedArray, inlined_cbor::InlinedCbor, redacted_claims::RedactedClaimKeys};

mod accessors;
mod sd_issued_codec;
mod sd_payload_codec;
mod sd_protected_codec;
mod sd_unprotected_codec;

#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct SdCwtIssued<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims> {
    pub protected: InlinedCbor<SdProtected<ProtectedClaims>>,
    pub sd_unprotected: SdUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<SdPayload<PayloadClaims>>,
    pub signature: serde_bytes::ByteBuf,
    #[builder(default)]
    _marker: core::marker::PhantomData<Hasher>,
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> PartialEq
    for SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    fn eq(&self, other: &Self) -> bool {
        self.protected.eq(&other.protected) && self.sd_unprotected.eq(&other.sd_unprotected) && self.payload.eq(&other.payload) && self.signature.eq(&other.signature)
    }
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct SdProtected<Extra: CustomClaims> {
    pub alg: Algorithm,
    pub sd_alg: SdHashAlg,
    #[builder(default)]
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdUnprotected<Extra: CustomClaims> {
    pub sd_claims: Option<SaltedArray>,
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
#[builder(derive(Debug))]
pub struct SdPayload<Extra: CwtAny> {
    pub cnf: cose_key_confirmation::KeyConfirmation,
    #[builder(default)]
    pub redacted_claim_keys: Option<RedactedClaimKeys>,
    pub inner: SdInnerPayload<Extra>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(strip_option))]
#[builder(derive(Debug))]
pub struct SdInnerPayload<Extra: CwtAny> {
    pub issuer: String,
    #[builder(default)]
    pub subject: Option<String>,
    #[builder(default)]
    pub audience: Option<String>,
    #[builder(default)]
    pub expiration: Option<i64>,
    #[builder(default)]
    pub not_before: Option<i64>,
    #[builder(default)]
    pub issued_at: Option<i64>,
    #[builder(default)]
    pub cti: Option<serde_bytes::ByteBuf>,
    #[builder(default)]
    pub cnonce: Option<serde_bytes::ByteBuf>,
    #[cfg(feature = "status")]
    pub status: status_list::StatusClaim,
    #[builder(default)]
    pub extra: Option<Extra>,
}

pub type SdCwtIssuedTagged<PayloadClaims, Hasher, ProtectedClaims = NoClaims, UnprotectedClaims = NoClaims> =
    ciborium::tag::Required<SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>;

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
        a: SdCwtIssuedTagged<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
        b: SdCwtIssuedTagged<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>,
    ) -> bool {
        a == b
    }
}
