pub fn verify_time_claims(
    now: u64,
    leeway: core::time::Duration,
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
    verification: TimeVerification,
) -> Result<(), CwtTimeError> {
    let now = now as i64;
    let leeway = i64::try_from(leeway.as_secs()).map_err(|_| CwtTimeError::LeewayTooLarge)?;

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
    if let Some(nbf) = nbf.filter(|_| verification.verify_nbf)
        && now.saturating_add(leeway) < nbf
    {
        return Err(CwtTimeError::NotValidYet);
    }

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
    if let Some(iat) = iat.filter(|_| verification.verify_iat)
        && iat > now.saturating_add(leeway)
    {
        return Err(CwtTimeError::ClockDrift);
    }

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    if let Some(exp) = exp.filter(|_| verification.verify_exp)
        && now.saturating_sub(leeway) > exp
    {
        return Err(CwtTimeError::Expired);
    }
    Ok(())
}

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TimeClaims {
    pub iat: Option<i64>,
    pub exp: Option<i64>,
    pub nbf: Option<i64>,
}

/// Logical constraints between the time claims of the SD-CWT and of the SD-KBT, regardless of the current time
/// see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-kbt-and-sd-cwt-verifier-val (steps 3 & 7)
pub fn verify_time_consistency(sd_cwt: TimeClaims, kbt: TimeClaims) -> Result<(), CwtTimeError> {
    type Cmp = fn(&i64, &i64) -> bool;
    let (le, lt, ge): (Cmp, Cmp, Cmp) = (i64::le, i64::lt, i64::ge);
    let checks = [
        (sd_cwt.nbf, le, sd_cwt.iat, "SD-CWT nbf <= SD-CWT iat"),
        (sd_cwt.nbf, lt, sd_cwt.exp, "SD-CWT nbf < SD-CWT exp"),
        (sd_cwt.iat, lt, sd_cwt.exp, "SD-CWT iat < SD-CWT exp"),
        (kbt.nbf, le, kbt.iat, "SD-KBT nbf <= SD-KBT iat"),
        (kbt.iat, lt, kbt.exp, "SD-KBT iat < SD-KBT exp"),
        (kbt.exp, le, sd_cwt.exp, "SD-KBT exp <= SD-CWT exp"),
        (kbt.nbf, ge, sd_cwt.nbf, "SD-KBT nbf >= SD-CWT nbf"),
        (kbt.iat, ge, sd_cwt.iat, "SD-KBT iat >= SD-CWT iat"),
        (kbt.nbf, lt, sd_cwt.exp, "SD-KBT nbf < SD-CWT exp"),
        (kbt.iat, lt, sd_cwt.exp, "SD-KBT iat < SD-CWT exp"),
        (kbt.iat, ge, sd_cwt.nbf, "SD-KBT iat >= SD-CWT nbf"),
    ];
    match checks.into_iter().find(|(a, cmp, b, _)| a.zip(*b).is_some_and(|(a, b)| !cmp(&a, &b))) {
        Some((.., constraint)) => Err(CwtTimeError::Inconsistent(constraint)),
        None => Ok(()),
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TimeVerification {
    /// verify issued expiry
    pub verify_exp: bool,
    /// verify issued at
    pub verify_iat: bool,
    /// verify not before
    pub verify_nbf: bool,
}

impl Default for TimeVerification {
    fn default() -> Self {
        Self {
            verify_exp: true,
            verify_iat: true,
            verify_nbf: true,
        }
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum TimeArg {
    /// Durating elapsed since UNIX_EPOCH
    Absolute(core::time::Duration),
    /// Duration from now
    Relative(core::time::Duration),
}

impl TimeArg {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_absolute(&self, now: core::time::Duration) -> core::time::Duration {
        match *self {
            Self::Absolute(d) => d,
            Self::Relative(d) => now + d,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CwtTimeError {
    #[error("Iat in the future, probably clock drift")]
    ClockDrift,
    #[error("Exp in the past, the token is expired")]
    Expired,
    #[error("Nbf in the future, the token is not valid yet")]
    NotValidYet,
    #[error("Supplied leeway is too large")]
    LeewayTooLarge,
    #[error("Inconsistent time claims, expected: {0}")]
    Inconsistent(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    #[test]
    fn iat() {
        // no iat verification
        verify_time_claims(10, Default::default(), None, None, None, Default::default()).unwrap();
        // iat < now
        verify_time_claims(10, Default::default(), Some(9), None, None, Default::default()).unwrap();
        // iat == now
        verify_time_claims(10, Default::default(), Some(10), None, None, Default::default()).unwrap();
        // iat > now
        std::assert_matches!(
            verify_time_claims(10, Default::default(), Some(20), None, None, Default::default()),
            Err(CwtTimeError::ClockDrift)
        );
    }

    #[test]
    fn exp() {
        // no exp verification
        verify_time_claims(10, Default::default(), None, None, None, Default::default()).unwrap();
        // exp > now
        verify_time_claims(10, Default::default(), None, Some(20), None, Default::default()).unwrap();
        // exp == now
        verify_time_claims(10, Default::default(), None, Some(10), None, Default::default()).unwrap();
        // exp == now -leeway
        verify_time_claims(10, Duration::from_secs(5), None, Some(5), None, Default::default()).unwrap();
        // exp > now - leeway
        std::assert_matches!(
            verify_time_claims(10, Duration::from_secs(5), None, Some(4), None, Default::default()),
            Err(CwtTimeError::Expired)
        );
    }

    #[test]
    fn consistency() {
        let t = |iat, exp, nbf| TimeClaims { iat, exp, nbf };
        let sd_cwt = t(Some(10), Some(100), Some(5));
        // absent claims are not compared
        verify_time_consistency(TimeClaims::default(), TimeClaims::default()).unwrap();
        verify_time_consistency(sd_cwt, t(Some(20), Some(100), Some(10))).unwrap();
        // boundaries
        verify_time_consistency(t(Some(10), Some(11), Some(10)), t(Some(10), Some(11), Some(10))).unwrap();

        let inconsistent = [
            (t(Some(10), None, Some(11)), TimeClaims::default()),
            (t(None, Some(10), Some(10)), TimeClaims::default()),
            (t(Some(10), Some(10), None), TimeClaims::default()),
            (TimeClaims::default(), t(Some(10), None, Some(11))),
            (TimeClaims::default(), t(Some(10), Some(10), None)),
            (sd_cwt, t(Some(20), Some(101), None)),
            (sd_cwt, t(Some(20), None, Some(4))),
            (sd_cwt, t(Some(9), None, None)),
            (t(None, Some(100), None), t(None, None, Some(100))),
            (t(None, Some(100), None), t(Some(100), None, None)),
            (t(None, None, Some(5)), t(Some(4), None, None)),
        ];
        for (sd_cwt, kbt) in inconsistent {
            std::assert_matches!(verify_time_consistency(sd_cwt, kbt), Err(CwtTimeError::Inconsistent(_)), "{sd_cwt:?} {kbt:?}");
        }
    }

    #[test]
    fn nbf() {
        // no nbf verification
        verify_time_claims(10, Default::default(), None, None, None, Default::default()).unwrap();
        // nbf < now
        verify_time_claims(10, Default::default(), None, None, Some(5), Default::default()).unwrap();
        // nbf == now
        verify_time_claims(10, Default::default(), None, None, Some(10), Default::default()).unwrap();
        // nbf == now + leeway
        verify_time_claims(10, Duration::from_secs(5), None, None, Some(15), Default::default()).unwrap();
        // nbf > now + leeway
        std::assert_matches!(
            verify_time_claims(10, Duration::from_secs(5), None, None, Some(16), Default::default()),
            Err(CwtTimeError::NotValidYet)
        );
    }
}
