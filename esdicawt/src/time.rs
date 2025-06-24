pub fn verify_time_claims(
    now: i64,
    leeway: core::time::Duration,
    iat: Option<i64>,
    exp: Option<i64>,
    nbf: Option<i64>,
    verification: TimeVerification,
) -> Result<(), CwtTimeError> {
    let leeway = i64::try_from(leeway.as_secs()).map_err(|_| CwtTimeError::LeewayTooLarge)?;
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
    if let Some(iat) = iat.filter(|_| verification.verify_iat) {
        if iat > now.saturating_add(leeway) {
            return Err(CwtTimeError::ClockDrift);
        }
    }
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    if let Some(exp) = exp.filter(|_| verification.verify_exp) {
        if now.saturating_sub(leeway) > exp {
            return Err(CwtTimeError::Expired);
        }
    }
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
    if let Some(nbf) = nbf.filter(|_| verification.verify_nbf) {
        if now.saturating_add(leeway) < nbf {
            return Err(CwtTimeError::NotValidYet);
        }
    }
    Ok(())
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
        assert!(matches!(
            verify_time_claims(10, Default::default(), Some(20), None, None, Default::default()),
            Err(CwtTimeError::ClockDrift)
        ));
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
        assert!(matches!(
            verify_time_claims(10, Duration::from_secs(5), None, Some(4), None, Default::default()),
            Err(CwtTimeError::Expired)
        ));
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
        assert!(matches!(
            verify_time_claims(10, Duration::from_secs(5), None, None, Some(16), Default::default()),
            Err(CwtTimeError::NotValidYet)
        ));
    }
}
