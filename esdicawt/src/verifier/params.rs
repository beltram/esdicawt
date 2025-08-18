use crate::time::TimeVerification;

#[derive(Default, Debug, Copy, Clone)]
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
    /// verification of SD-CWT time claims
    pub sd_cwt_time_verification: TimeVerification,
    /// verification of SD-KBT time claims
    pub sd_kbt_time_verification: TimeVerification,
    /// when verifying a delayed message or testing
    pub artificial_time: Option<i64>,
}

impl VerifierParams<'_> {
    pub(crate) fn shallow(&self) -> ShallowVerifierParams {
        ShallowVerifierParams {
            sd_cwt_leeway: self.sd_cwt_leeway,
            sd_kbt_leeway: self.sd_kbt_leeway,
            sd_cwt_time_verification: self.sd_cwt_time_verification,
            sd_kbt_time_verification: self.sd_kbt_time_verification,
            artificial_time: self.artificial_time,
        }
    }
}

#[derive(Default, Debug, Copy, Clone)]
pub struct ShallowVerifierParams {
    // to accommodate clock skews, applies to iat, exp & nbf of the SD-CWT
    pub sd_cwt_leeway: core::time::Duration,
    // to accommodate clock skews, applies to iat, exp & nbf of the SD-KBT
    pub sd_kbt_leeway: core::time::Duration,
    /// verification of SD-CWT time claims
    pub sd_cwt_time_verification: TimeVerification,
    /// verification of SD-KBT time claims
    pub sd_kbt_time_verification: TimeVerification,
    /// when verifying a delayed message or testing
    pub artificial_time: Option<i64>,
}
