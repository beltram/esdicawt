pub struct VerifierParams {
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    /// for testing
    pub artificial_time: Option<i64>,
}
