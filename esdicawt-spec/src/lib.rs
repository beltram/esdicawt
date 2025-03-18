pub mod alg;
pub mod blinded_claims;
pub mod inlined_cbor;
pub mod issuance;
pub mod key_binding;
pub mod redacted_claims;
pub mod select;
pub mod verified;

pub use select::*;

pub mod reexports {
    pub use ciborium;
    pub use coset;
}

pub const COSE_SD_CLAIMS: i64 = 17;
pub const COSE_SD_KBT: i64 = 18;

/// Used for redacted claims in an array
/// TODO: Pending IANA registration. Later on we should get it via coset
pub const REDACTED_CLAIM_ELEMENT_TAG: u64 = 60;
pub const TO_BE_REDACTED_TAG: u64 = 58;

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
pub const CWT_CLAIM_CNONCE: i64 = coset::iana::CwtClaimName::CNonce as i64;
pub const CWT_CLAIM_CTI: i64 = coset::iana::CwtClaimName::Cti as i64;

// FIXME: this is not in the draft yet
// Use as a SimpleType. It works thanks to an unmerged fork of ciborium
pub const CWT_LABEL_REDACTED_KEYS: u8 = 59;

// TODO: register it in coset IANA registry
pub const COSE_HEADER_KCWT: i64 = 13;

pub const CWT_MEDIATYPE: i64 = 16;
pub const MEDIATYPE_SD_CWT: &str = "application/sd+cwt";
pub const MEDIATYPE_KB_CWT: &str = "application/kb+cwt";

pub type EsdicawtSpecResult<T> = Result<T, EsdicawtSpecError>;

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
    #[error("Should have been a mapping")]
    InputError,
    #[error("{0}")]
    ImplementationError(&'static str),
}

impl From<Value> for EsdicawtSpecError {
    fn from(_: Value) -> Self {
        Self::InputError
    }
}

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
pub enum SdCwtStandardClaim {
    Issuer = CWT_CLAIM_ISSUER,
    Subject = CWT_CLAIM_SUBJECT,
    Audience = CWT_CLAIM_AUDIENCE,
    ExpiresAt = CWT_CLAIM_EXPIRES_AT,
    NotBefore = CWT_CLAIM_NOT_BEFORE,
    IssuedAt = CWT_CLAIM_ISSUED_AT,
    Cnonce = CWT_CLAIM_CNONCE,
    Cti = CWT_CLAIM_CTI,
    KeyConfirmation = CWT_CLAIM_KEY_CONFIRMATION_MAP,
}

impl TryFrom<i64> for SdCwtStandardClaim {
    type Error = EsdicawtSpecError;
    fn try_from(value: i64) -> Result<Self, Self::Error> {
        Ok(match value {
            CWT_CLAIM_ISSUER => Self::Issuer,
            CWT_CLAIM_SUBJECT => Self::Subject,
            CWT_CLAIM_AUDIENCE => Self::Audience,
            CWT_CLAIM_EXPIRES_AT => Self::ExpiresAt,
            CWT_CLAIM_NOT_BEFORE => Self::NotBefore,
            CWT_CLAIM_ISSUED_AT => Self::IssuedAt,
            CWT_CLAIM_CNONCE => Self::Cnonce,
            CWT_CLAIM_CTI => Self::Cti,
            CWT_CLAIM_KEY_CONFIRMATION_MAP => Self::KeyConfirmation,
            value => return Err(EsdicawtSpecError::UnknownStandardClaim(value)),
        })
    }
}

impl TryFrom<&Value> for SdCwtStandardClaim {
    type Error = EsdicawtSpecError;
    fn try_from(label: &Value) -> Result<Self, Self::Error> {
        Ok(match label {
            Value::Integer(i) if i == &CWT_CLAIM_ISSUER.into() => Self::Issuer,
            Value::Integer(i) if i == &CWT_CLAIM_SUBJECT.into() => Self::Subject,
            Value::Integer(i) if i == &CWT_CLAIM_AUDIENCE.into() => Self::Audience,
            Value::Integer(i) if i == &CWT_CLAIM_EXPIRES_AT.into() => Self::ExpiresAt,
            Value::Integer(i) if i == &CWT_CLAIM_NOT_BEFORE.into() => Self::NotBefore,
            Value::Integer(i) if i == &CWT_CLAIM_ISSUED_AT.into() => Self::IssuedAt,
            Value::Integer(i) if i == &CWT_CLAIM_CNONCE.into() => Self::Cnonce,
            Value::Integer(i) if i == &CWT_CLAIM_CTI.into() => Self::Cti,
            Value::Integer(i) if i == &CWT_CLAIM_KEY_CONFIRMATION_MAP.into() => Self::KeyConfirmation,
            Value::Integer(i) => return Err(EsdicawtSpecError::UnknownStandardClaim(i64::try_from(*i)?)),
            _ => return Err(EsdicawtSpecError::InputError),
        })
    }
}

#[derive(Debug, Clone, Copy, serde_repr::Serialize_repr, serde_repr::Deserialize_repr)]
#[repr(i64)]
#[non_exhaustive]
pub enum KbtStandardClaim {
    Audience = CWT_CLAIM_AUDIENCE,
    ExpiresAt = CWT_CLAIM_EXPIRES_AT,
    NotBefore = CWT_CLAIM_NOT_BEFORE,
    IssuedAt = CWT_CLAIM_ISSUED_AT,
    Cnonce = CWT_CLAIM_CNONCE,
}

impl TryFrom<ciborium::value::Integer> for KbtStandardClaim {
    type Error = EsdicawtSpecError;
    fn try_from(label: ciborium::value::Integer) -> Result<Self, Self::Error> {
        Ok(match i64::try_from(label) {
            Ok(CWT_CLAIM_AUDIENCE) => Self::Audience,
            Ok(CWT_CLAIM_EXPIRES_AT) => Self::ExpiresAt,
            Ok(CWT_CLAIM_NOT_BEFORE) => Self::NotBefore,
            Ok(CWT_CLAIM_ISSUED_AT) => Self::IssuedAt,
            Ok(CWT_CLAIM_CNONCE) => Self::Cnonce,
            Err(_) => return Err(Self::Error::ImplementationError("Invalid CWT label")),
            Ok(label) => return Err(Self::Error::UnknownStandardClaim(label)),
        })
    }
}

#[derive(Clone, Hash, PartialEq, Eq)]
pub enum ClaimName {
    Integer(i64),
    Text(String),
    TaggedInteger(u64, i64),
    TaggedText(u64, String),
    SimpleValue(u8),
}

impl ClaimName {
    pub fn untag(&self) -> Option<Self> {
        match self {
            Self::TaggedText(tag, label) if *tag == TO_BE_REDACTED_TAG => Some(Self::Text(label.to_owned())),
            Self::TaggedInteger(tag, label) if *tag == TO_BE_REDACTED_TAG => Some(Self::Integer(label.to_owned())),
            _ => None,
        }
    }
}

impl std::fmt::Debug for ClaimName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Integer(i) => write!(f, "{i}"),
            Self::Text(s) => write!(f, "{s}"),
            Self::TaggedInteger(t, i) => write!(f, "#6.{t}({i})"),
            Self::TaggedText(t, s) => write!(f, "#6.{t}({s})"),
            Self::SimpleValue(st) => write!(f, "simple({st})"),
        }
    }
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

pub trait CustomClaims: std::fmt::Debug + CwtAny + Clone {}

impl<T> CustomClaims for T where T: std::fmt::Debug + CwtAny + Clone {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoClaims;

impl serde::Serialize for NoClaims {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_none()
    }
}

impl<'de> serde::Deserialize<'de> for NoClaims {
    fn deserialize<D: serde::Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
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
