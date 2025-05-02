#[derive(Default, Debug, Clone)]
pub struct VerifierParams<'a> {
    pub expected_subject: Option<&'a str>,
    pub expected_issuer: Option<&'a str>,
    pub expected_audience: Option<&'a str>,
    pub expected_kbt_audience: Option<&'a str>,
    pub expected_cnonce: Option<&'a [u8]>,
    // to accommodate clock skews, applies to iat, exp & nbf of the SD-CWT
    pub sd_cwt_leeway: core::time::Duration,
    // to accommodate clock skews, applies to iat, exp & nbf of the SD-KBT
    pub sd_kbt_leeway: core::time::Duration,
    /// when verifying a delayed message or testing
    pub artificial_time: Option<i64>,
}
