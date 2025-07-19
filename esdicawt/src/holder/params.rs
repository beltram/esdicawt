use crate::{SdCwtHolderResult, TimeVerification, holder::traverse::traverse_all_cbor_paths_in_disclosures, time::TimeArg};
use ciborium::Value;
use esdicawt_spec::{ClaimName, CustomClaims, NoClaims, blinded_claims::SaltedArray};

#[derive(Debug)]
pub struct HolderParams<'a, KbtPayloadClaims: CustomClaims = NoClaims, KbtProtectedClaims: CustomClaims = NoClaims, KbtUnprotectedClaims: CustomClaims = NoClaims> {
    pub presentation: Presentation,
    /// Subject, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.3
    pub audience: &'a str,
    /// Client Nonce, see https://www.rfc-editor.org/rfc/rfc9200.html#section-5.3.1
    pub cnonce: Option<&'a [u8]>,
    /// Expiry, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.4
    pub expiry: Option<TimeArg>,
    /// Whether to include a not_before, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.5
    pub with_not_before: bool,
    pub artificial_time: Option<core::time::Duration>,
    pub time_verification: TimeVerification,
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    pub extra_kbt_protected: Option<KbtProtectedClaims>,
    pub extra_kbt_unprotected: Option<KbtUnprotectedClaims>,
    pub extra_kbt_payload: Option<KbtPayloadClaims>,
}

#[derive(Default)]
pub enum Presentation {
    #[default]
    Full,
    Custom(Box<dyn Fn(SaltedArray) -> SaltedArray>),
    #[allow(clippy::type_complexity)]
    Path(Box<dyn Fn(&[CborPath]) -> bool>),
    None,
}

impl std::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::Custom(_) => write!(f, "Custom"),
            Self::Path(_) => write!(f, "Path"),
            Self::None => write!(f, "None"),
        }
    }
}

impl Presentation {
    pub(crate) fn try_select_disclosures<Hasher: digest::Digest, E: core::error::Error + Send + Sync>(&self, disclosures: SaltedArray) -> SdCwtHolderResult<SaltedArray, E> {
        Ok(match self {
            Self::Full => disclosures,
            Self::None => SaltedArray(vec![]),
            Self::Custom(f) => f(disclosures),
            Self::Path(f) => {
                let hashed_disclosures = disclosures.digested::<Hasher>()?;
                let cbor_paths = traverse_all_cbor_paths_in_disclosures::<Hasher, E>(&hashed_disclosures)?;
                let cbor_paths = cbor_paths
                    .into_iter()
                    .filter_map(|(path, salted, ..)| f(&path).then_some(salted.into()))
                    .collect::<Vec<_>>();
                SaltedArray(cbor_paths)
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CborPath {
    Str(String),
    Int(i64),
    Any(Value),
    Index(u64),
}

impl From<&ClaimName> for CborPath {
    fn from(name: &ClaimName) -> Self {
        match name {
            ClaimName::Integer(i) => Self::Int(*i),
            ClaimName::Text(s) => Self::Str(s.clone()),
            ClaimName::TaggedInteger(tag, i) => Self::Any(Value::Tag(*tag, Box::new((*i).into()))),
            ClaimName::TaggedText(tag, s) => Self::Any(Value::Tag(*tag, Box::new(s.as_str().into()))),
            ClaimName::SimpleValue(i) => Self::Any(Value::Simple(*i)),
        }
    }
}

impl TryFrom<&Value> for CborPath {
    type Error = core::num::TryFromIntError;

    fn try_from(name: &Value) -> Result<Self, Self::Error> {
        Ok(match name {
            Value::Integer(i) => Self::Int((*i).try_into()?),
            Value::Text(s) => Self::Str(s.clone()),
            value => Self::Any(value.clone()),
        })
    }
}
