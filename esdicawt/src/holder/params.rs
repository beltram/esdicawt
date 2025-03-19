use esdicawt_spec::CustomClaims;
use esdicawt_spec::blinded_claims::SaltedArray;

#[derive(Debug)]
pub struct HolderParams<'a, KbtProtectedClaims: CustomClaims, KbtUnprotectedClaims: CustomClaims, KbtPayloadClaims: CustomClaims> {
    pub presentation: Presentation,
    pub audience: &'a str,
    pub expiry: core::time::Duration,
    pub leeway: core::time::Duration,
    pub extra_kbt_protected: Option<KbtProtectedClaims>,
    pub extra_kbt_unprotected: Option<KbtUnprotectedClaims>,
    pub extra_kbt_payload: Option<KbtPayloadClaims>,
}

#[derive(Default)]
pub enum Presentation {
    #[default]
    Full,
    Custom(Box<dyn FnOnce(SaltedArray) -> SaltedArray>),
    None,
}

impl Presentation {
    pub fn select_disclosures(&self, disclosures: SaltedArray) -> SaltedArray {
        disclosures
    }
}

impl std::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::Custom(_) => write!(f, "Custom"),
            Self::None => write!(f, "None"),
        }
    }
}
