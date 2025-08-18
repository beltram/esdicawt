use std::time::Duration;

#[derive(Debug, Clone)]
pub struct StatusListIssuerParams {
    /// The subject claim MUST specify the URI of the Status List Token.
    /// The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token
    pub uri: url::Url,
    /// Allows setting an arbitrary time which can be useful for example when fudging the issuance time
    pub artificial_time: Option<core::time::Duration>,
    /// As generally defined in [RFC8392](https://www.rfc-editor.org/rfc/rfc8392).
    /// The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer
    pub expiry: Option<TimeArg>,
    /// The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
    /// The value of the claim MUST be a positive number
    pub ttl: Option<Duration>,
    pub key_id: Option<Vec<u8>>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TimeArg {
    /// Durating elapsed since UNIX_EPOCH
    Absolute(core::time::Duration),
    /// Duration from now
    Relative(core::time::Duration),
}

impl TimeArg {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_absolute(&self, now: core::time::Duration) -> core::time::Duration {
        match *self {
            Self::Absolute(d) => d,
            Self::Relative(d) => now + d,
        }
    }
}
