use cose_key_confirmation::KeyConfirmation;
use esdicawt_spec::{CustomClaims, Select};

pub struct IssuerParams<'a, PayloadClaims: Select, ProtectedClaims: CustomClaims, UnprotectedClaims: CustomClaims> {
    /// Extra claims in the protected header of the sd-cwt
    pub protected_claims: Option<ProtectedClaims>,
    /// Extra claims in the unprotected header of the sd-cwt
    pub unprotected_claims: Option<UnprotectedClaims>,
    /// CBOR value with tagged claims to disclose
    pub payload: Option<PayloadClaims>,
    pub subject: &'a str,
    /// Used to be inserted in the Issuer claim
    pub issuer: &'a str,
    pub expiry: core::time::Duration,
    /// Dealing with clocks skew
    pub leeway: core::time::Duration,
    pub key_location: &'a str,
    pub holder_confirmation_key: KeyConfirmation,
}
