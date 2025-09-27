use crate::alg::Algorithm;
use crate::{blinded_claims::SaltedArray, inlined_cbor::InlinedCbor, redacted_claims::RedactedClaimKeys, CustomClaims, EsdicawtSpecResult, SelectiveDisclosureHashAlg};
use cose_key_confirmation::KeyConfirmation;

mod sd_issued_payload_codec;
mod sd_payload_codec;
mod sd_protected_codec;
mod unprotected_issued_codec;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
#[builder(derive(Debug))]
pub struct SelectiveDisclosurePayload<E: CustomClaims> {
    pub inner: SdCwtPayload<E>,
    pub key_confirmation: KeyConfirmation,
    #[builder(default)]
    pub redacted_claim_keys: Option<RedactedClaimKeys>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
#[builder(derive(Debug))]
pub struct SdCwtPayload<E: CustomClaims> {
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
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdUnprotected<E: CustomClaims> {
    pub sd_claims: InlinedCbor<SaltedArray>,
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct SelectiveDisclosureProtected<E: CustomClaims> {
    pub alg: Algorithm,
    pub sd_alg: SelectiveDisclosureHashAlg,
    #[builder(default)]
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct SelectiveDisclosureIssued<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> {
    pub protected: InlinedCbor<SelectiveDisclosureProtected<ProtectedClaims>>,
    pub sd_unprotected: SdUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<SelectiveDisclosurePayload<PayloadClaims>>,
    pub signature: Vec<u8>,
    pub _disclosable: core::marker::PhantomData<DisclosableClaims>,
}

pub type SelectiveDisclosureIssuedTagged<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims> = ciborium::tag::Required<
    SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>,
    { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG },
>;

impl<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims>
    SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosableClaims>
{
    pub fn disclosures(&mut self) -> EsdicawtSpecResult<&SaltedArray> {
        self.sd_unprotected.sd_claims.to_value()
    }
}
