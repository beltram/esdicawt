use crate::time::TimeArg;
use cose_key_confirmation::KeyConfirmation;
use esdicawt_spec::{CustomClaims, NoClaims, Select};

#[derive(Debug, Clone)]
pub struct IssuerParams<'a, PayloadClaims: Select, ProtectedClaims: CustomClaims = NoClaims, UnprotectedClaims: CustomClaims = NoClaims> {
    /// Extra claims in the protected header of the sd-cwt
    pub protected_claims: Option<ProtectedClaims>,
    /// Extra claims in the unprotected header of the sd-cwt
    pub unprotected_claims: Option<UnprotectedClaims>,
    /// CBOR value with tagged claims to disclose
    pub payload: Option<PayloadClaims>,
    /// Issuer, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.1
    pub issuer: &'a str,
    /// Subject, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.2
    pub subject: Option<&'a str>,
    /// Subject, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.3
    pub audience: Option<&'a str>,
    /// Expiry, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.4
    pub expiry: Option<TimeArg>,
    /// Whether to include a not_before, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.5
    pub with_not_before: bool,
    /// Whether to include an issued_at, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.6
    pub with_issued_at: bool,
    /// CWT ID, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.7
    pub cti: Option<&'a [u8]>,
    /// Client Nonce, see https://www.rfc-editor.org/rfc/rfc9200.html#section-5.3.1
    pub cnonce: Option<&'a [u8]>,
    #[cfg(feature = "test-vectors")]
    pub artificial_time: Option<core::time::Duration>,
    /// Dealing with clocks skew
    pub leeway: core::time::Duration,
    pub key_location: &'a str,
    pub holder_confirmation_key: KeyConfirmation,
}
