use crate::alg::Algorithm;
use crate::blinded_claims::SaltedArray;
use crate::issuance::SelectiveDisclosurePayload;
use crate::{CustomClaims, EsdicawtSpecResult, blinded_claims::Salted, inlined_cbor::InlinedCbor, issuance::SelectiveDisclosureIssuedTagged};

mod kbt_codec;
mod kbt_payload_codec;
mod kbt_protected_codec;
mod kbt_unprotected_codec;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct KeyBindingTokenPayload<E: CustomClaims> {
    #[builder(default)]
    pub audience: String,
    #[builder(default)]
    pub expiration: Option<i64>,
    #[builder(default)]
    pub not_before: Option<i64>,
    pub issued_at: i64,
    #[builder(default)]
    pub client_nonce: Option<Vec<u8>>,
    #[builder(default)]
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: CustomClaims")]
pub struct KeyBindingTokenUnprotected<E> {
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct KeyBindingTokenProtected<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    E: CustomClaims,
    DisclosedClaims: CustomClaims,
> {
    pub alg: Algorithm,
    /// In the 'kcwt' claim
    /// See https://datatracker.ietf.org/doc/html/rfc9528#section-3.5.3.1
    pub issuer_sd_cwt: InlinedCbor<SelectiveDisclosureIssuedTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, DisclosedClaims>>,
    #[builder(default)]
    pub claims: Option<E>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct KeyBindingToken<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> {
    pub protected: InlinedCbor<KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, DisclosedClaims>>,
    pub unprotected: KeyBindingTokenUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<KeyBindingTokenPayload<PayloadClaims>>,
    pub signature: Vec<u8>,
    pub _disclosed: core::marker::PhantomData<DisclosedClaims>,
}

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>
{
    pub fn sd_cwt_payload(&mut self) -> EsdicawtSpecResult<&SelectiveDisclosurePayload<IssuerPayloadClaims>> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.issuer_sd_cwt.to_value_mut()?;
        let payload = sd_cwt.0.payload.to_value()?;
        Ok(payload)
    }

    pub fn disclosures(&mut self) -> EsdicawtSpecResult<&SaltedArray> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.issuer_sd_cwt.to_value_mut()?;
        sd_cwt.0.disclosures()
    }
}

pub type KeyBindingTokenTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims> =
    ciborium::tag::Required<
        KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>,
        { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG },
    >;

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> KeyBindingToken<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims, DisclosedClaims>
{
    /// Iterates through all the disclosed claims in this SD-KBT
    pub fn walk_disclosed_claims(&mut self) -> EsdicawtSpecResult<impl Iterator<Item = EsdicawtSpecResult<Salted<ciborium::Value>>> + '_> {
        let protected = self.protected.to_value_mut()?;
        let issuer_sd_cwt = protected.issuer_sd_cwt.to_value_mut()?;
        Ok(issuer_sd_cwt.0.sd_unprotected.sd_claims.to_value()?.iter())
    }
}
