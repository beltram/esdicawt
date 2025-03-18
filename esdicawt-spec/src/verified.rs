use crate::{
    CustomClaims, EsdicawtSpecError, NoClaims, Select,
    alg::Algorithm,
    issuance::{SdCwtIssued, SdInnerPayload, SdProtected, SdUnprotected},
    key_binding::{KbtPayload, KbtProtected, KbtUnprotected},
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: Select")]
pub struct KbtCwtVerified<
    IssuerPayloadClaims: Select,
    IssuerProtectedClaims: CustomClaims = NoClaims,
    IssuerUnprotectedClaims: CustomClaims = NoClaims,
    KbtProtectedClaims: CustomClaims = NoClaims,
    KbtUnprotectedClaims: CustomClaims = NoClaims,
    KbtPayloadClaims: CustomClaims = NoClaims,
> {
    pub protected: KbtCwtProtectedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims>,
    pub unprotected: KbtUnprotected<KbtUnprotectedClaims>,
    pub payload: KbtPayload<KbtPayloadClaims>,
    pub claimset: IssuerPayloadClaims,
}

impl<
    IssuerPayloadClaims: Select,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> KbtCwtVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims>
{
    pub fn sd_cwt(&self) -> &SdIssuedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims> {
        &self.protected.issuer_sd_cwt
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: CustomClaims")]
pub struct KbtCwtProtectedVerified<IssuerPayloadClaims: Select, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims> {
    pub alg: Algorithm,
    pub issuer_sd_cwt: SdIssuedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims>,
    pub claims: Option<Extra>,
}

impl<IssuerPayloadClaims: Select, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims>
    TryFrom<KbtProtected<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>>
    for KbtCwtProtectedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: KbtProtected<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>) -> Result<Self, Self::Error> {
        Ok(Self {
            alg: v.alg,
            issuer_sd_cwt: v.kcwt.try_into_value()?.0.try_into()?,
            claims: v.extra,
        })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "ProtectedClaims: CustomClaims")]
pub struct SdIssuedVerified<PayloadClaims: CustomClaims, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> {
    pub protected: SdProtected<ProtectedClaims>,
    pub sd_unprotected: SdUnprotectedVerified<UnprotectedClaims>,
    pub payload: SdInnerPayload<PayloadClaims>,
}

impl<PayloadClaims: Select, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> TryFrom<SdCwtIssued<PayloadClaims, ProtectedClaims, UnprotectedClaims>>
    for SdIssuedVerified<PayloadClaims, ProtectedClaims, UnprotectedClaims>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: SdCwtIssued<PayloadClaims, ProtectedClaims, UnprotectedClaims>) -> Result<Self, Self::Error> {
        Ok(Self {
            protected: v.protected.try_into_value()?,
            sd_unprotected: v.sd_unprotected.into(),
            payload: v.payload.try_into_value()?.inner,
        })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "Extra: CustomClaims")]
pub struct SdUnprotectedVerified<Extra: CustomClaims> {
    pub claims: Option<Extra>,
}

impl<Extra: CustomClaims> From<SdUnprotected<Extra>> for SdUnprotectedVerified<Extra> {
    fn from(v: SdUnprotected<Extra>) -> Self {
        Self { claims: v.extra }
    }
}
