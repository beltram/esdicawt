use crate::{
    spec::{CustomClaims, NoClaims, Select},
    time::TimeArg,
};
use cose_key::confirmation::KeyConfirmation;

/// The 'sub' claim of a SD-CWT, it MUST be present either redacted or not
/// see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-sd-cwt-claims
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subject<'a> {
    Redacted(&'a str),
    Unredacted(&'a str),
}

impl<'a> From<&'a str> for Subject<'a> {
    fn from(subject: &'a str) -> Self {
        Self::Unredacted(subject)
    }
}

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
    /// Subject, MUST be present, see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-sd-cwt-claims
    pub subject: Subject<'a>,
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
    #[cfg(feature = "status")]
    pub status: StatusParams,
}

#[cfg(feature = "status")]
#[derive(Debug, Clone)]
pub struct StatusParams {
    pub status_list_bit_index: status_list::BitIndex,
    pub uri: url::Url,
}
