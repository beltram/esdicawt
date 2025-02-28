use std::collections::HashMap;

pub mod alg;
pub mod blinded_claims;
pub mod inlined_cbor;
pub mod issuance;
pub mod key_binding;
pub mod redacted_claims;
pub mod verified;

pub mod reexports {
    pub use ciborium;
    pub use coset;
}

pub const COSE_SD_CLAIMS: i64 = 17;
pub const COSE_SD_KBT: i64 = 18;

/// Used for redacted claims in an array
/// TODO: Pending IANA registration. Later on we should get it via coset
pub const REDACTED_CLAIM_ELEMENT_TAG: u64 = 60;

pub const CWT_CLAIM_ALG: i64 = 1;
pub const CWT_CLAIM_SD_ALG: i64 = 12;
pub const CWT_CLAIM_ISSUER_SD_CWT: i64 = 11;
pub const CWT_CLAIM_REDACTED_ELEMENT: i64 = 41;
pub const CWT_CLAIM_VCT: i64 = 42;
pub const CWT_CLAIM_ISSUER: i64 = coset::iana::CwtClaimName::Iss as i64;
pub const CWT_CLAIM_SUBJECT: i64 = coset::iana::CwtClaimName::Sub as i64;
pub const CWT_CLAIM_AUDIENCE: i64 = coset::iana::CwtClaimName::Aud as i64;
pub const CWT_CLAIM_EXPIRES_AT: i64 = coset::iana::CwtClaimName::Exp as i64;
pub const CWT_CLAIM_NOT_BEFORE: i64 = coset::iana::CwtClaimName::Nbf as i64;
pub const CWT_CLAIM_ISSUED_AT: i64 = coset::iana::CwtClaimName::Iat as i64;
pub const CWT_CLAIM_KEY_CONFIRMATION_MAP: i64 = coset::iana::CwtClaimName::Cnf as i64;
pub const CWT_CLAIM_CLIENT_NONCE: i64 = coset::iana::CwtClaimName::CNonce as i64;

// FIXME: this is not in the draft yet
// Use as a SimpleType. It works thanks to an unmerged fork of ciborium
pub const CWT_LABEL_REDACTED_KEYS: u8 = 59;

// TODO: register it in coset IANA registry
pub const COSE_HEADER_KCWT: i64 = 13;

pub const CWT_MEDIATYPE: i64 = 16;
pub const MEDIATYPE_SD_CWT: &str = "application/sd+cwt";
pub const MEDIATYPE_KB_CWT: &str = "application/kb+cwt";

#[derive(Debug, thiserror::Error)]
pub enum EsdicawtSpecError {
    #[error("The following claim is unknown: {0}")]
    UnknownStandardClaim(i64),
    #[error(transparent)]
    InvalidCwtIntKey(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    SdPayloadBuilderError(#[from] issuance::SdPayloadBuilderError),
    #[error(transparent)]
    SdInnerPayloadBuilderError(#[from] issuance::SdInnerPayloadBuilderError),
    #[error(transparent)]
    SdProtectedBuilderError(#[from] issuance::SdProtectedBuilderError),
    #[error(transparent)]
    KbtPayloadBuilderError(#[from] key_binding::KbtPayloadBuilderError),
    #[error(transparent)]
    KbtProtectedBuilderError(#[from] key_binding::KbtProtectedBuilderError),
    #[error(transparent)]
    CborDeserializationError(#[from] ciborium::de::Error<std::io::Error>),
    #[error(transparent)]
    CborSerializationError(#[from] ciborium::ser::Error<std::io::Error>),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
}

pub type EsdicawtSpecResult<T> = Result<T, EsdicawtSpecError>;

pub use ciborium::{Value, cbor};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
pub enum SdHashAlg {
    Sha256 = coset::iana::Algorithm::SHA_256 as i64,
    Sha384 = coset::iana::Algorithm::SHA_384 as i64,
    Sha512 = coset::iana::Algorithm::SHA_512 as i64,
    Shake256 = coset::iana::Algorithm::SHAKE256 as i64,
    Shake128 = coset::iana::Algorithm::SHAKE128 as i64,
    Sha512_256 = coset::iana::Algorithm::SHA_512_256 as i64,
    Sha256_64 = coset::iana::Algorithm::SHA_256_64 as i64,
    Sha1 = coset::iana::Algorithm::SHA_1 as i64,
}

#[derive(Debug, Clone, Copy, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
#[non_exhaustive]
pub enum SelectiveDisclosureStandardClaim {
    IssuerClaim = CWT_CLAIM_ISSUER,
    SubjectClaim = CWT_CLAIM_SUBJECT,
    AudienceClaim = CWT_CLAIM_AUDIENCE,
    ExpiresAtClaim = CWT_CLAIM_EXPIRES_AT,
    NotBeforeClaim = CWT_CLAIM_NOT_BEFORE,
    IssuedAtClaim = CWT_CLAIM_ISSUED_AT,
    KeyConfirmationClaim = CWT_CLAIM_KEY_CONFIRMATION_MAP,
}

impl TryFrom<i64> for SelectiveDisclosureStandardClaim {
    type Error = EsdicawtSpecError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(match value {
            CWT_CLAIM_ISSUER => Self::IssuerClaim,
            CWT_CLAIM_SUBJECT => Self::SubjectClaim,
            CWT_CLAIM_AUDIENCE => Self::AudienceClaim,
            CWT_CLAIM_EXPIRES_AT => Self::ExpiresAtClaim,
            CWT_CLAIM_NOT_BEFORE => Self::NotBeforeClaim,
            CWT_CLAIM_ISSUED_AT => Self::IssuedAtClaim,
            CWT_CLAIM_KEY_CONFIRMATION_MAP => Self::KeyConfirmationClaim,
            value => return Err(EsdicawtSpecError::UnknownStandardClaim(value)),
        })
    }
}

#[derive(Debug, Clone, Copy, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
#[non_exhaustive]
pub enum KbtStandardClaim {
    AudienceClaim = CWT_CLAIM_AUDIENCE,
    ExpiresAtClaim = CWT_CLAIM_EXPIRES_AT,
    NotBeforeClaim = CWT_CLAIM_NOT_BEFORE,
    IssuedAtClaim = CWT_CLAIM_ISSUED_AT,
    ClientNonceClaim = CWT_CLAIM_CLIENT_NONCE,
}

impl TryFrom<i64> for KbtStandardClaim {
    type Error = EsdicawtSpecError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(match value {
            CWT_CLAIM_AUDIENCE => Self::AudienceClaim,
            CWT_CLAIM_EXPIRES_AT => Self::ExpiresAtClaim,
            CWT_CLAIM_NOT_BEFORE => Self::NotBeforeClaim,
            CWT_CLAIM_ISSUED_AT => Self::IssuedAtClaim,
            CWT_CLAIM_CLIENT_NONCE => Self::ClientNonceClaim,
            value => return Err(EsdicawtSpecError::UnknownStandardClaim(value)),
        })
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum ClaimName {
    Integer(i64),
    Text(String),
    TaggedInteger(u64, i64),
    TaggedText(u64, String),
    SimpleValue(u8),
}

impl serde::Serialize for ClaimName {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let value = match self {
            Self::Integer(i) => (*i).into(),
            Self::Text(s) => s.as_str().into(),
            Self::TaggedInteger(t, i) => Value::Tag(*t, Box::new((*i).into())),
            Self::TaggedText(t, s) => Value::Tag(*t, Box::new(s.as_str().into())),
            Self::SimpleValue(st) => Value::Simple(*st),
        };
        Value::serialize(&value, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ClaimName {
    fn deserialize<D: serde::de::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        // Only rely on this if the claim key is in the top-level CWT payload. If the Mapping is nested, no such key restriction apply
        let value = <Value as serde::Deserialize>::deserialize(deserializer)?;
        Ok(match value {
            Value::Simple(i) => Self::SimpleValue(i),
            Value::Integer(i) => Self::Integer(i.try_into().map_err(D::Error::custom)?),
            Value::Text(s) => Self::Text(s),
            Value::Tag(tag, v) => match *v {
                Value::Integer(i) => Self::TaggedInteger(tag, i.try_into().map_err(D::Error::custom)?),
                Value::Text(s) => Self::TaggedText(tag, s),
                _ => return Err(D::Error::custom("Only String, integers in tags at the root of a CWT payload")),
            },
            _ => return Err(D::Error::custom("Only String, integers are allowed in the root of a CWT payload")),
        })
    }
}

impl From<i64> for ClaimName {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<&str> for ClaimName {
    fn from(value: &str) -> Self {
        Self::Text(value.into())
    }
}

pub type MapKey = ClaimName;

pub trait CwtAny: serde::Serialize + for<'de> serde::Deserialize<'de> {
    fn to_cbor_bytes(&self) -> EsdicawtSpecResult<Vec<u8>> {
        let mut buf = vec![];
        ciborium::into_writer(self, &mut buf)?;
        Ok(buf)
    }

    fn from_cbor_bytes(bytes: &[u8]) -> EsdicawtSpecResult<Self>
    where
        Self: Sized,
    {
        Ok(ciborium::from_reader(bytes)?)
    }
}

impl<T> CwtAny for T where T: serde::Serialize + for<'de> serde::Deserialize<'de> {}

pub type AnyMap = HashMap<MapKey, Value>;

pub trait CustomClaims: std::fmt::Debug + CwtAny + Clone + Into<AnyMap> + TryFrom<AnyMap> {}
impl<T> CustomClaims for T where T: std::fmt::Debug + CwtAny + Clone + Into<AnyMap> + TryFrom<AnyMap> {}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NoClaims;

impl From<NoClaims> for AnyMap {
    fn from(_: NoClaims) -> Self {
        Self::default()
    }
}

impl TryFrom<AnyMap> for NoClaims {
    type Error = std::convert::Infallible;

    fn try_from(_: AnyMap) -> Result<Self, Self::Error> {
        Ok(Self)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct Salt(#[serde(with = "serde_bytes")] pub [u8; Salt::SIZE]);

impl Salt {
    pub const SIZE: usize = 16;

    pub fn empty() -> Self {
        Self([0; Self::SIZE])
    }
}

impl std::ops::Deref for Salt {
    type Target = [u8; Self::SIZE];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for Salt {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
