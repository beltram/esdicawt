use crate::{Status, StatusList};

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(strip_option))]
pub struct StatusListToken<S: Status = u8> {
    #[builder(default)]
    pub alg: Option<coset::iana::Algorithm>,
    #[builder(default)]
    pub key_id: Option<Vec<u8>>,
    /// As generally defined in [RFC8392]. The subject claim MUST specify the URI of the Status List Token.
    /// The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token
    pub sub: url::Url,
    /// As generally defined in [RFC8392]. The issued at claim MUST specify the time at which the Status List Token was issued
    pub iat: i64,
    /// As generally defined in [RFC8392]. The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer
    #[builder(default)]
    pub exp: Option<i64>,
    /// Unsigned integer (Major Type 0). The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
    /// The value of the claim MUST be a positive number
    #[builder(default)]
    pub ttl: Option<u64>,
    pub status_list: StatusList<S>,
    pub signature: serde_bytes::ByteBuf,
}
