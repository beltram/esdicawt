use crate::{
    CustomClaims, EsdicawtSpecResult, NoClaims, Select,
    alg::Algorithm,
    blinded_claims::{Salted, SaltedArray},
    inlined_cbor::InlinedCbor,
    issuance::{SdCwtIssuedTagged, SdPayload},
};

mod kbt_codec;
mod kbt_payload_codec;
mod kbt_protected_codec;
mod kbt_unprotected_codec;
mod accessors;

#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(pattern = "mutable")]
pub struct KbtCwt<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    PayloadClaims: CustomClaims = NoClaims,
    IssuerProtectedClaims: CustomClaims = NoClaims,
    IssuerUnprotectedClaims: CustomClaims = NoClaims,
    ProtectedClaims: CustomClaims = NoClaims,
    UnprotectedClaims: CustomClaims = NoClaims,
> {
    pub protected: InlinedCbor<KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims>>,
    pub unprotected: KbtUnprotected<UnprotectedClaims>,
    pub payload: InlinedCbor<KbtPayload<PayloadClaims>>,
    pub signature: serde_bytes::ByteBuf,
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    PayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
> PartialEq for KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    fn eq(&self, other: &Self) -> bool {
        self.protected.eq(&other.protected) && self.unprotected.eq(&other.unprotected) && self.payload.eq(&other.payload) && self.signature.eq(&other.signature)
    }
}

#[derive(Debug, Clone, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(into, strip_option))]
pub struct KbtProtected<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    Extra: CustomClaims,
> {
    pub alg: Algorithm,
    /// See https://datatracker.ietf.org/doc/html/rfc9528#section-3.5.3.1
    pub kcwt: InlinedCbor<SdCwtIssuedTagged<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>>,
    #[builder(default)]
    pub extra: Option<Extra>,
}

impl<IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims> PartialEq
    for KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
{
    fn eq(&self, other: &Self) -> bool {
        let Ok(self_kcwt) = self.kcwt.as_bytes() else { return false };
        let Ok(other_kcwt) = other.kcwt.as_bytes() else { return false };
        self.alg.eq(&other.alg) && self_kcwt.eq(&other_kcwt) && self.extra.eq(&other.extra)
    }
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
    pub cnonce: Option<serde_bytes::ByteBuf>,
    #[builder(default)]
    pub extra: Option<Extra>,
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    pub fn sd_cwt_payload(&mut self) -> EsdicawtSpecResult<&SdPayload<IssuerPayloadClaims>> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        let payload = sd_cwt.0.payload.to_value()?;
        Ok(payload)
    }

    pub fn disclosures(&mut self) -> EsdicawtSpecResult<Option<&SaltedArray>> {
        let protected = self.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        Ok(sd_cwt.0.disclosures())
    }
}

pub type KbtCwtTagged<
    IssuerPayloadClaims,
    Hasher,
    PayloadClaims = NoClaims,
    IssuerProtectedClaims = NoClaims,
    IssuerUnprotectedClaims = NoClaims,
    ProtectedClaims = NoClaims,
    UnprotectedClaims = NoClaims,
> = ciborium::tag::Required<
    KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>,
    { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG },
>;

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
> KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    /// Iterates through all the disclosed claims in this SD-KBT
    pub fn walk_disclosed_claims(&mut self) -> EsdicawtSpecResult<Box<dyn Iterator<Item = EsdicawtSpecResult<&Salted<ciborium::Value>>> + '_>> {
        let protected = self.protected.to_value_mut()?;
        let issuer_sd_cwt = protected.kcwt.to_value_mut()?;

        #[allow(clippy::option_if_let_else)]
        if let Some(sd_claims) = issuer_sd_cwt.0.disclosures_mut() {
            Ok(Box::new(sd_claims.iter()))
        } else {
            Ok(Box::new(core::iter::empty()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(dead_code)]
    fn should_be_comparable<
        IssuerPayloadClaims: Select,
        Hasher: digest::Digest + Clone,
        IssuerProtectedClaims: CustomClaims,
        IssuerUnprotectedClaims: CustomClaims,
        ProtectedClaims: CustomClaims,
        UnprotectedClaims: CustomClaims,
        PayloadClaims: CustomClaims,
    >(
        a: KbtCwtTagged<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>,
        b: KbtCwtTagged<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>,
    ) -> bool {
        a == b
    }
}
