use crate::{CustomClaims, EsdicawtSpecResult, SdHashAlg, alg::Algorithm, blinded_claims::SaltedArray, inlined_cbor::InlinedCbor, redacted_claims::RedactedClaimKeys};

mod sd_issued_payload_codec;
mod sd_payload_codec;
mod sd_protected_codec;
mod unprotected_issued_codec;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct SdCwtIssued<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> {
    pub protected: InlinedCbor<SdProtected<ProtectedClaims>>,
    pub sd_unprotected: SdUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<SdPayload<PayloadClaims>>,
    pub signature: Vec<u8>,
    pub _disclosable: core::marker::PhantomData<DisclosableClaims>,
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
    pub sd_claims: InlinedCbor<SaltedArray>,
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
#[builder(derive(Debug))]
pub struct SdPayload<Extra: CustomClaims> {
    pub cnf: cose_key_confirmation::KeyConfirmation,
    #[builder(default)]
    pub redacted_claim_keys: Option<RedactedClaimKeys>,
    pub inner: SdInnerPayload<Extra>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
#[builder(derive(Debug))]
pub struct SdInnerPayload<Extra: CustomClaims> {
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
    pub extra: Option<Extra>,
}

pub type SdCwtIssuedTagged<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims> =
    ciborium::tag::Required<SdCwtIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>;

impl<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims>
    SdCwtIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>
{
    pub fn disclosures(&mut self) -> EsdicawtSpecResult<&SaltedArray> {
        self.sd_unprotected.sd_claims.to_value()
    }
}
