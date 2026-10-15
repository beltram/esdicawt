pub fn verify_time_claims(now: u64, leeway: core::time::Duration, claims: TimeClaims) -> Result<(), CwtTimeError> {
    let now = now as i64;
    let leeway = i64::try_from(leeway.as_secs()).map_err(|_| CwtTimeError::LeewayTooLarge)?;

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
    if let Some(nbf) = claims.nbf
        && now.saturating_add(leeway) < nbf
    {
        return Err(CwtTimeError::NotValidYet);
    }

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
    if let Some(iat) = claims.iat
        && iat > now.saturating_add(leeway)
    {
        return Err(CwtTimeError::ClockDrift);
    }

    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    if let Some(exp) = claims.exp
        && now.saturating_sub(leeway) > exp
    {
        return Err(CwtTimeError::Expired);
    }
    Ok(())
}

/// Time claims of a token whose verification is enabled
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct TimeClaims {
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
}

impl TimeClaims {
    /// Only keeps the claims whose verification is enabled
    pub fn new(iat: Option<i64>, exp: Option<i64>, nbf: Option<i64>, verification: TimeVerification) -> Self {
        Self {
            iat: iat.filter(|_| verification.verify_iat),
            exp: exp.filter(|_| verification.verify_exp),
            nbf: nbf.filter(|_| verification.verify_nbf),
        }
    }
}

/// Logical constraints between the time claims of the SD-CWT and of the SD-KBT, regardless of the current time.
/// The claims of each token are set by a different clock (Issuer's and Holder's), so in the constraints across tokens
/// each claim may be off by the leeway of its token.
/// see https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-kbt-and-sd-cwt-verifier-val (steps 3 & 7)
pub fn verify_time_consistency(sd_cwt: TimeClaims, sd_cwt_leeway: core::time::Duration, kbt: TimeClaims, kbt_leeway: core::time::Duration) -> Result<(), CwtTimeError> {
    /// (lower, its leeway, upper, its leeway, strict, constraint)
    type Check = (Option<i64>, i64, Option<i64>, i64, bool, &'static str);
    let secs = |leeway: core::time::Duration| i64::try_from(leeway.as_secs()).map_err(|_| CwtTimeError::LeewayTooLarge);
    // within a token, both claims are set by the same clock
    let (same_clock, sd, kb) = (0, secs(sd_cwt_leeway)?, secs(kbt_leeway)?);
    let checks: [Check; 11] = [
        (sd_cwt.nbf, same_clock, sd_cwt.iat, same_clock, false, "SD-CWT nbf <= SD-CWT iat"),
        (sd_cwt.nbf, same_clock, sd_cwt.exp, same_clock, true, "SD-CWT nbf < SD-CWT exp"),
        (sd_cwt.iat, same_clock, sd_cwt.exp, same_clock, true, "SD-CWT iat < SD-CWT exp"),
        (kbt.nbf, same_clock, kbt.iat, same_clock, false, "SD-KBT nbf <= SD-KBT iat"),
        (kbt.iat, same_clock, kbt.exp, same_clock, true, "SD-KBT iat < SD-KBT exp"),
        (kbt.exp, kb, sd_cwt.exp, sd, false, "SD-KBT exp <= SD-CWT exp"),
        (sd_cwt.nbf, sd, kbt.nbf, kb, false, "SD-KBT nbf >= SD-CWT nbf"),
        (sd_cwt.iat, sd, kbt.iat, kb, false, "SD-KBT iat >= SD-CWT iat"),
        (kbt.nbf, kb, sd_cwt.exp, sd, true, "SD-KBT nbf < SD-CWT exp"),
        (kbt.iat, kb, sd_cwt.exp, sd, true, "SD-KBT iat < SD-CWT exp"),
        (sd_cwt.nbf, sd, kbt.iat, kb, false, "SD-KBT iat >= SD-CWT nbf"),
    ];
    let violated = |&(lower, lower_leeway, upper, upper_leeway, strict, _): &Check| {
        lower.zip(upper).is_some_and(|(lower, upper)| {
            let (lower, upper) = (lower.saturating_sub(lower_leeway), upper.saturating_add(upper_leeway));
            if strict { lower >= upper } else { lower > upper }
        })
    };
    match checks.iter().find(|c| violated(c)) {
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
        verify_time_claims(10, Default::default(), t(None, None, None)).unwrap();
        // iat < now
        verify_time_claims(10, Default::default(), t(Some(9), None, None)).unwrap();
        // iat == now
        verify_time_claims(10, Default::default(), t(Some(10), None, None)).unwrap();
        // iat > now
        std::assert_matches!(verify_time_claims(10, Default::default(), t(Some(20), None, None)), Err(CwtTimeError::ClockDrift));
    }

    #[test]
    fn exp() {
        // no exp verification
        verify_time_claims(10, Default::default(), t(None, None, None)).unwrap();
        // exp > now
        verify_time_claims(10, Default::default(), t(None, Some(20), None)).unwrap();
        // exp == now
        verify_time_claims(10, Default::default(), t(None, Some(10), None)).unwrap();
        // exp == now -leeway
        verify_time_claims(10, Duration::from_secs(5), t(None, Some(5), None)).unwrap();
        // exp > now - leeway
        std::assert_matches!(verify_time_claims(10, Duration::from_secs(5), t(None, Some(4), None)), Err(CwtTimeError::Expired));
    }

    fn t(iat: Option<i64>, exp: Option<i64>, nbf: Option<i64>) -> TimeClaims {
        TimeClaims::new(iat, exp, nbf, Default::default())
    }

    fn consistent(sd_cwt: TimeClaims, kbt: TimeClaims) -> Result<(), CwtTimeError> {
        verify_time_consistency(sd_cwt, Duration::ZERO, kbt, Duration::ZERO)
    }

    #[test]
    fn consistency() {
        let sd_cwt = t(Some(10), Some(100), Some(5));
        // absent claims are not compared
        consistent(t(None, None, None), t(None, None, None)).unwrap();
        consistent(sd_cwt, t(Some(20), Some(100), Some(10))).unwrap();
        // boundaries
        consistent(t(Some(10), Some(11), Some(10)), t(Some(10), Some(11), Some(10))).unwrap();

        let inconsistent = [
            (t(Some(10), None, Some(11)), t(None, None, None)),
            (t(None, Some(10), Some(10)), t(None, None, None)),
            (t(Some(10), Some(10), None), t(None, None, None)),
            (t(None, None, None), t(Some(10), None, Some(11))),
            (t(None, None, None), t(Some(10), Some(10), None)),
            (sd_cwt, t(Some(20), Some(101), None)),
            (sd_cwt, t(Some(20), None, Some(4))),
            (sd_cwt, t(Some(9), None, None)),
            (t(None, Some(100), None), t(None, None, Some(100))),
            (t(None, Some(100), None), t(Some(100), None, None)),
            (t(None, None, Some(5)), t(Some(4), None, None)),
        ];
        for (sd_cwt, kbt) in inconsistent {
            std::assert_matches!(consistent(sd_cwt, kbt), Err(CwtTimeError::Inconsistent(_)), "{sd_cwt:?} {kbt:?}");
        }
    }

    #[test]
    fn consistency_leeway() {
        let secs = Duration::from_secs;
        let inconsistent = |r| std::assert_matches!(r, Err(CwtTimeError::Inconsistent(_)));
        // Holder's clock 5s behind the Issuer's
        let (sd_cwt, kbt) = (t(Some(100), Some(200), Some(100)), t(Some(95), Some(205), Some(95)));
        inconsistent(consistent(sd_cwt, kbt));
        // tolerated by either leeway or by both combined
        verify_time_consistency(sd_cwt, secs(5), kbt, secs(0)).unwrap();
        verify_time_consistency(sd_cwt, secs(0), kbt, secs(5)).unwrap();
        verify_time_consistency(sd_cwt, secs(2), kbt, secs(3)).unwrap();
        // the smaller leeway is not raised to the larger one
        inconsistent(verify_time_consistency(sd_cwt, secs(2), kbt, secs(2)));
        inconsistent(verify_time_consistency(sd_cwt, secs(4), kbt, secs(0)));
        // Holder's clock 5s ahead of the Issuer's, after the SD-CWT expiry
        let (sd_cwt, kbt) = (t(None, Some(100), None), t(Some(104), None, Some(104)));
        verify_time_consistency(sd_cwt, secs(2), kbt, secs(3)).unwrap();
        inconsistent(verify_time_consistency(sd_cwt, secs(2), t(Some(105), None, None), secs(3)));
        // not applicable within a token
        inconsistent(verify_time_consistency(t(Some(10), Some(10), None), secs(5), t(None, None, None), secs(5)));
        inconsistent(verify_time_consistency(t(None, None, None), secs(5), t(Some(10), Some(10), None), secs(5)));
    }

    #[test]
    fn consistency_skips_unverified_claims() {
        let no_exp = TimeVerification {
            verify_exp: false,
            ..Default::default()
        };
        // fresh SD-KBT of an expired SD-CWT
        let (sd_cwt, kbt) = (t(Some(10), Some(100), None), t(Some(200), None, None));
        std::assert_matches!(consistent(sd_cwt, kbt), Err(CwtTimeError::Inconsistent(_)));
        let unverified_exp = TimeClaims::new(Some(10), Some(100), None, no_exp);
        assert_eq!(unverified_exp, t(Some(10), None, None));
        consistent(unverified_exp, kbt).unwrap();
    }

    #[test]
    fn nbf() {
        // no nbf verification
        verify_time_claims(10, Default::default(), t(None, None, None)).unwrap();
        // nbf < now
        verify_time_claims(10, Default::default(), t(None, None, Some(5))).unwrap();
        // nbf == now
        verify_time_claims(10, Default::default(), t(None, None, Some(10))).unwrap();
        // nbf == now + leeway
        verify_time_claims(10, Duration::from_secs(5), t(None, None, Some(15))).unwrap();
        // nbf > now + leeway
        std::assert_matches!(verify_time_claims(10, Duration::from_secs(5), t(None, None, Some(16))), Err(CwtTimeError::NotValidYet));
    }
}
