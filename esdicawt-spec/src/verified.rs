use crate::{
    CustomClaims, EsdicawtSpecError,
    alg::Algorithm,
    issuance::{SdCwtIssued, SdInnerPayload, SdProtected, SdUnprotected},
    key_binding::{KbtPayload, KbtProtected, KbtUnprotected},
};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: CustomClaims, DisclosedClaims: CustomClaims")]
pub struct KbtCwtVerified<
    DisclosedClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> {
    pub protected: KbtCwtProtectedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, KbtProtectedClaims>,
    pub unprotected: KbtUnprotected<KbtUnprotectedClaims>,
    pub payload: KbtPayload<KbtPayloadClaims>,
    pub claimset: DisclosedClaims,
}

impl<
    DisclosedClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> KbtCwtVerified<DisclosedClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims>
{
    pub fn sd_cwt(&self) -> &SdIssuedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims> {
        &self.protected.issuer_sd_cwt
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "IssuerProtectedClaims: CustomClaims")]
pub struct KbtCwtProtectedVerified<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, Extra: CustomClaims> {
    pub alg: Algorithm,
    pub issuer_sd_cwt: SdIssuedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims>,
    pub claims: Option<Extra>,
}

impl<DisclosedClaims: CustomClaims, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: CustomClaims, Extra: CustomClaims>
    TryFrom<KbtProtected<DisclosedClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, Extra>>
    for KbtCwtProtectedVerified<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, Extra>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: KbtProtected<DisclosedClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, Extra>) -> Result<Self, Self::Error> {
        Ok(Self {
            alg: v.alg,
            issuer_sd_cwt: v.kcwt.try_into_value()?.0.try_into()?,
            claims: v.extra,
        })
    }
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(bound = "ProtectedClaims: CustomClaims")]
pub struct SdIssuedVerified<ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims> {
    pub protected: SdProtected<ProtectedClaims>,
    pub sd_unprotected: SdUnprotectedVerified<UnprotectedClaims>,
    pub payload: SdInnerPayload<PayloadClaims>,
}

impl<DisclosableClaims: CustomClaims, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims>
    TryFrom<SdCwtIssued<DisclosableClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims>> for SdIssuedVerified<ProtectedClaims, UnprotectedClaims, PayloadClaims>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: SdCwtIssued<DisclosableClaims, ProtectedClaims, UnprotectedClaims, PayloadClaims>) -> Result<Self, Self::Error> {
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
