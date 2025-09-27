use crate::{
    CustomClaims, EsdicawtSpecError, NoClaims, Select,
    alg::Algorithm,
    issuance::{SdCwtIssued, SdInnerPayload, SdProtected, SdUnprotected},
    key_binding::{KbtPayload, KbtProtected, KbtUnprotected},
};

#[derive(Debug, Clone, PartialEq)]
pub struct KbtCwtVerified<
    IssuerPayloadClaims: Select,
    KbtPayloadClaims: CustomClaims = NoClaims,
    IssuerProtectedClaims: CustomClaims = NoClaims,
    IssuerUnprotectedClaims: CustomClaims = NoClaims,
    KbtProtectedClaims: CustomClaims = NoClaims,
    KbtUnprotectedClaims: CustomClaims = NoClaims,
> {
    pub protected: KbtProtectedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims>,
    pub unprotected: KbtUnprotected<KbtUnprotectedClaims>,
    pub payload: KbtPayload<KbtPayloadClaims>,
    pub claimset: Option<IssuerPayloadClaims>,
}

impl<
    IssuerPayloadClaims: Select,
    KbtPayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
> KbtCwtVerified<IssuerPayloadClaims, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    pub fn sd_cwt(&self) -> &SdIssuedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims> {
        &self.protected.issuer_sd_cwt
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct KbtProtectedVerified<
    IssuerPayloadClaims: Select,
    IssuerProtectedClaims: CustomClaims = NoClaims,
    IssuerUnprotectedClaims: CustomClaims = NoClaims,
    Extra: CustomClaims = NoClaims,
> {
    pub alg: Algorithm,
    pub issuer_sd_cwt: SdIssuedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims>,
    pub claims: Option<Extra>,
}

impl<IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, Extra: CustomClaims>
    TryFrom<KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>>
    for KbtProtectedVerified<IssuerPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: KbtProtected<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, Extra>) -> Result<Self, Self::Error> {
        Ok(Self {
            alg: v.alg,
            issuer_sd_cwt: v.kcwt.try_into_value()?.0.try_into()?,
            claims: v.extra,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdIssuedVerified<PayloadClaims: CustomClaims, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims> {
    pub protected: SdProtected<ProtectedClaims>,
    pub sd_unprotected: SdUnprotectedVerified<UnprotectedClaims>,
    pub payload: SdInnerPayload<PayloadClaims>,
    pub cnf: cose_key_confirmation::KeyConfirmation,
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims>
    TryFrom<SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>> for SdIssuedVerified<PayloadClaims, ProtectedClaims, UnprotectedClaims>
{
    type Error = EsdicawtSpecError;

    fn try_from(v: SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>) -> Result<Self, Self::Error> {
        let payload = v.payload.try_into_value()?;
        Ok(Self {
            protected: v.protected.try_into_value()?,
            sd_unprotected: v.sd_unprotected.into(),
            payload: payload.inner,
            cnf: payload.cnf,
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SdUnprotectedVerified<Extra: CustomClaims = NoClaims> {
    pub claims: Option<Extra>,
}

impl<Extra: CustomClaims> From<SdUnprotected<Extra>> for SdUnprotectedVerified<Extra> {
    fn from(v: SdUnprotected<Extra>) -> Self {
        Self { claims: v.extra }
    }
}
