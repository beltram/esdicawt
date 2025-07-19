use crate::{issuance::SdCwtIssued, key_binding::KbtCwt, CustomClaims, EsdicawtSpecResult, Select};

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    PayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    ProtectedClaims: CustomClaims,
    UnprotectedClaims: CustomClaims,
> KbtCwt<IssuerPayloadClaims, Hasher, PayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, ProtectedClaims, UnprotectedClaims>
{
    /// Get the SD-CWT wrapped by this SD-KBT
    pub fn sd_cwt(&mut self) -> EsdicawtSpecResult<&SdCwtIssued<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>> {
        Ok(&self.protected.to_value_mut()?.kcwt.to_value()?.0)
    }
}
