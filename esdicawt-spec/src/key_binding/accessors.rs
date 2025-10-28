use crate::{CustomClaims, EsdicawtSpecResult, Select, issuance::SdCwtIssued, key_binding::KbtCwt};

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

    /// Get the SD-CWT wrapped by this SD-KBT
    pub fn sd_cwt_mut(&mut self) -> EsdicawtSpecResult<&mut SdCwtIssued<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>> {
        Ok(&mut self.protected.to_value_mut()?.kcwt.to_value_mut()?.0)
    }

    /// SD-KBT expiration, different from SD-CWT one !!!
    pub fn exp(&mut self) -> EsdicawtSpecResult<Option<u64>> {
        Ok(self.payload.to_value()?.expiration.map(|e| e as u64))
    }

    /// SD-KBT issued at, different from SD-CWT one !!!
    pub fn iat(&mut self) -> EsdicawtSpecResult<u64> {
        Ok(self.payload.to_value()?.issued_at as u64)
    }

    /// SD-KBT not before, different from SD-CWT one !!!
    pub fn nbf(&mut self) -> EsdicawtSpecResult<Option<u64>> {
        Ok(self.payload.to_value()?.not_before.map(|e| e as u64))
    }

    /// SD-KBT audience, different from SD-CWT one !!!
    pub fn audience(&mut self) -> EsdicawtSpecResult<&str> {
        Ok(&self.payload.to_value()?.audience)
    }

    /// SD-KBT client nonce, different from SD-CWT one !!!
    pub fn client_nonce(&mut self) -> EsdicawtSpecResult<Option<&[u8]>> {
        Ok(self.payload.to_value()?.cnonce.as_deref().map(|b| &b[..]))
    }

    /// Signature algorithm of the SD-KBT, not the SD-CWT one !!!
    pub fn alg(&mut self) -> Option<coset::iana::Algorithm> {
        match *self.protected.to_value().ok()?.alg {
            coset::Algorithm::Assigned(alg) => Some(alg),
            _ => None,
        }
    }

    #[cfg(feature = "status")]
    pub fn status(&mut self) -> EsdicawtSpecResult<Option<status_list::StatusClaim>> {
        Ok(self.sd_cwt_mut()?.status())
    }
}
