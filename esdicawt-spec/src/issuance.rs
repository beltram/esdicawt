use crate::{CustomClaims, CwtAny, NoClaims, SdHashAlg, Select, alg::Algorithm, blinded_claims::SaltedArray, inlined_cbor::InlinedCbor, redacted_claims::RedactedClaimKeys};

mod sd_issued_codec;
mod sd_payload_codec;
mod sd_protected_codec;
mod sd_unprotected_codec;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct SdCwtIssued<PayloadClaims: Select, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims> {
    pub protected: InlinedCbor<SdProtected<ProtectedClaims>>,
    pub sd_unprotected: SdUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<SdPayload<PayloadClaims>>,
    pub signature: Vec<u8>,
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
    pub sd_claims: SaltedArray,
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
#[builder(pattern = "mutable", setter(into, strip_option))]
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
    pub cti: Option<Vec<u8>>,
    #[builder(default)]
    pub cnonce: Option<Vec<u8>>,
    #[builder(default)]
    pub extra: Option<Extra>,
}

pub type SdCwtIssuedTagged<PayloadClaims, ProtectedClaims = NoClaims, UnprotectedClaims = NoClaims> =
    ciborium::tag::Required<SdCwtIssued<PayloadClaims, ProtectedClaims, UnprotectedClaims>, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>;

impl<PayloadClaims: Select, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> SdCwtIssued<PayloadClaims, ProtectedClaims, UnprotectedClaims> {
    pub fn disclosures(&self) -> &SaltedArray {
        &self.sd_unprotected.sd_claims
    }

    pub fn disclosures_mut(&mut self) -> &mut SaltedArray {
        &mut self.sd_unprotected.sd_claims
    }
}
