use crate::StatusList;

#[derive(Debug, Clone, PartialEq, derive_builder::Builder)]
#[builder(pattern = "mutable", setter(strip_option))]
pub struct StatusListToken {
    /// As generally defined in [RFC8392]. The subject claim MUST specify the URI of the Status List Token.
    /// The value MUST be equal to that of the uri claim contained in the status_list claim of the Referenced Token
    pub sub: url::Url,
    /// As generally defined in [RFC8392]. The issued at claim MUST specify the time at which the Status List Token was issued
    pub iat: u64,
    /// As generally defined in [RFC8392]. The expiration time claim, if present, MUST specify the time at which the Status List Token is considered expired by its issuer
    pub exp: Option<u64>,
    /// Unsigned integer (Major Type 0). The time to live claim, if present, MUST specify the maximum amount of time, in seconds, that the Status List Token can be cached by a consumer before a fresh copy SHOULD be retrieved.
    /// The value of the claim MUST be a positive number
    pub ttl: Option<u64>,
    pub status_list: StatusList,
    pub signature: serde_bytes::ByteBuf,
}

pub type StatusListTokenTagged = ciborium::tag::Required<String, { <coset::CoseSign1 as coset::TaggedCborSerializable>::TAG }>;
