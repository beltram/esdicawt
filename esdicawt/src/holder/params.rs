use esdicawt_spec::CustomClaims;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HolderParams<'a, KbtProtectedClaims: CustomClaims, KbtUnprotectedClaims: CustomClaims, KbtPayloadClaims: CustomClaims> {
    pub presentation: Presentation,
    pub audience: &'a str,
    pub expiry: core::time::Duration,
    pub leeway: core::time::Duration,
    pub extra_kbt_protected: Option<KbtProtectedClaims>,
    pub extra_kbt_unprotected: Option<KbtUnprotectedClaims>,
    pub extra_kbt_payload: Option<KbtPayloadClaims>,
}

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Presentation {
    #[default]
    Full,
}
