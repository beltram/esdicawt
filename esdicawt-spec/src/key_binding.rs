use crate::{
    CustomClaims, EsdicawtSpecResult, Select,
    alg::Algorithm,
    blinded_claims::{Salted, SaltedArray},
    inlined_cbor::InlinedCbor,
    issuance::{SdCwtIssuedTagged, SdPayload},
};

mod kbt_codec;
mod kbt_payload_codec;
mod kbt_protected_codec;
mod kbt_unprotected_codec;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct KbtCwt<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: Select,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> {
    pub protected: InlinedCbor<KbtProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims>>,
    pub unprotected: KbtUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<KbtPayload<PayloadClaims>>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct KbtProtected<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: Select, Extra: CustomClaims> {
    pub alg: Algorithm,
    /// See https://datatracker.ietf.org/doc/html/rfc9528#section-3.5.3.1
    pub kcwt: InlinedCbor<SdCwtIssuedTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims>>,
    #[builder(default)]
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "Extra: CustomClaims")]
pub struct KbtUnprotected<Extra: CustomClaims> {
    #[serde(flatten, default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Extra>,
}

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct KbtPayload<Extra: CustomClaims> {
    #[builder(default)]
    pub audience: String,
    #[builder(default)]
    pub expiration: Option<i64>,
    #[builder(default)]
    pub not_before: Option<i64>,
    pub issued_at: i64,
    #[builder(default)]
    pub cnonce: Option<Vec<u8>>,
    #[builder(default)]
    pub extra: Option<Extra>,
}

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: Select,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> KbtCwt<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims>
{
    pub fn sd_cwt_payload(&mut self) -> EsdicawtSpecResult<&SdPayload<IssuerPayloadClaims>> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        let payload = sd_cwt.0.payload.to_value()?;
        Ok(payload)
    }

    pub fn disclosures(&mut self) -> EsdicawtSpecResult<&SaltedArray> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        sd_cwt.0.disclosures()
    }
}

pub type KbtCwtTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims> = ciborium::tag::Required<
    KbtCwt<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims>,
    { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG },
>;

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: Select,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> KbtCwt<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims>
{
    /// Iterates through all the disclosed claims in this SD-KBT
    pub fn walk_disclosed_claims(&mut self) -> EsdicawtSpecResult<impl Iterator<Item = EsdicawtSpecResult<Salted<ciborium::Value>>> + '_> {
        let protected = self.protected.to_value_mut()?;
        let issuer_sd_cwt = protected.kcwt.to_value_mut()?;
        Ok(issuer_sd_cwt.0.sd_unprotected.sd_claims.to_value()?.iter())
    }
}
