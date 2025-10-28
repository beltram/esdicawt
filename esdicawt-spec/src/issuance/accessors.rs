use crate::{CustomClaims, EsdicawtSpecError, EsdicawtSpecResult, Select, issuance::SdCwtIssued};
use cose_key_confirmation::KeyConfirmation;

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims>
    SdCwtIssued<PayloadClaims, Hasher, ProtectedClaims, UnprotectedClaims>
{
    /// Get the confirmation key
    pub fn cnf<K>(&mut self) -> EsdicawtSpecResult<K>
    where
        for<'a> K: TryFrom<&'a KeyConfirmation, Error: Into<EsdicawtSpecError>>,
    {
        (&self.payload.to_value()?.cnf).try_into().map_err(Into::into)
    }

    /// Signature algorithm of the SD-CWT
    pub fn alg(&mut self) -> Option<coset::iana::Algorithm> {
        match *self.protected.to_value().ok()?.alg {
            coset::Algorithm::Assigned(alg) => Some(alg),
            _ => None,
        }
    }

    #[cfg(feature = "status")]
    pub fn status(&mut self) -> Option<status_list::StatusClaim> {
        Some(self.payload.as_value().ok()?.inner.status.clone())
    }
}
