#[derive(Default, Debug, Clone)]
pub struct VerifierParams<'a> {
    pub expected_subject: Option<&'a str>,
    pub expected_issuer: Option<&'a str>,
    pub expected_audience: Option<&'a str>,
    pub expected_kbt_audience: Option<&'a str>,
    pub expected_cnonce: Option<&'a [u8]>,
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    /// for testing
    pub artificial_time: Option<i64>,
}
