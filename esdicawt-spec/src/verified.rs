use crate::alg::Algorithm;
use crate::{
    CustomClaims, EsdicawtSpecError,
    issuance::{SdCwtPayload, SdUnprotected, SelectiveDisclosureIssued, SelectiveDisclosureProtected},
    key_binding::{KeyBindingTokenPayload, KeyBindingTokenProtected, KeyBindingTokenUnprotected},
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: CustomClaims, DisclosedClaims: CustomClaims")]
pub struct KeyBindingTokenVerified<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> {
    pub protected: KeyBindingTokenProtectedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, KbtProtectedClaims>,
    pub unprotected: KeyBindingTokenUnprotected<KbtUnprotectedClaims>,
    pub payload: KeyBindingTokenPayload<KbtPayloadClaims>,
    pub claimset: DisclosedClaims,
}

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
    DisclosedClaims: CustomClaims,
> KeyBindingTokenVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims, DisclosedClaims>
{
    pub fn sd_cwt(&self) -> &SelectiveDisclosureIssuedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims> {
        &self.protected.issuer_sd_cwt
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: CustomClaims")]
pub struct KeyBindingTokenProtectedVerified<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims> {
    pub alg: Algorithm,
    pub issuer_sd_cwt: SelectiveDisclosureIssuedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims>,
    pub claims: Option<E>,
}

impl<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, E: CustomClaims, D: CustomClaims>
    TryFrom<KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, D>>
    for KeyBindingTokenProtectedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: KeyBindingTokenProtected<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, E, D>) -> Result<Self, Self::Error> {
        Ok(Self {
            alg: v.alg,
            issuer_sd_cwt: v.issuer_sd_cwt.try_into_value()?.0.try_into()?,
            claims: v.claims,
        })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "ProtectedClaims: CustomClaims")]
pub struct SelectiveDisclosureIssuedVerified<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims> {
    pub protected: SelectiveDisclosureProtected<ProtectedClaims>,
    pub sd_unprotected: SdUnprotectedVerified<UnprotectedClaims>,
    pub payload: SdCwtPayload<PayloadClaims>,
}

impl<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, E: CustomClaims>
    TryFrom<SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, E>>
    for SelectiveDisclosureIssuedVerified<ProtectedClaims, UnprotectedClaims, PayloadClaims>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: SelectiveDisclosureIssued<ProtectedClaims, UnprotectedClaims, PayloadClaims, E>) -> Result<Self, Self::Error> {
        Ok(Self {
            protected: v.protected.try_into_value()?,
            sd_unprotected: v.sd_unprotected.into(),
            payload: v.payload.try_into_value()?.inner,
        })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "E: CustomClaims")]
pub struct SdUnprotectedVerified<E: CustomClaims> {
    pub claims: Option<E>,
}

impl<E: CustomClaims> From<SdUnprotected<E>> for SdUnprotectedVerified<E> {
    fn from(v: SdUnprotected<E>) -> Self {
        Self { claims: v.claims }
    }
}
