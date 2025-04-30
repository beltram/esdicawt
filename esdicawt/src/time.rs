pub fn verify_time_claims(now: i64, leeway: core::time::Duration, iat: Option<i64>, exp: Option<i64>, nbf: Option<i64>) -> Result<(), CwtTimeError> {
    let leeway = i64::try_from(leeway.as_secs()).map_err(|_| CwtTimeError::LeewayTooLarge)?;
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
    if let Some(iat) = iat {
        if iat >= now {
            return Err(CwtTimeError::ClockDrift);
        }
    }
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    if let Some(exp) = exp {
        if now.saturating_sub(leeway) > exp {
            return Err(CwtTimeError::Expired);
        }
    }
    // see https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
    if let Some(nbf) = nbf {
        if now.saturating_add(leeway) < nbf {
            return Err(CwtTimeError::NotValidYet);
        }
    }
    Ok(())
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
        verify_time_claims(10, Default::default(), None, None, None).unwrap();
        // iat < now
        verify_time_claims(10, Default::default(), Some(9), None, None).unwrap();
        // iat == now
        verify_time_claims(10, Default::default(), Some(10), None, None).unwrap();
        // iat > now
        assert!(matches!(verify_time_claims(10, Default::default(), Some(20), None, None), Err(CwtTimeError::ClockDrift)));
    }

    #[test]
    fn exp() {
        // no exp verification
        verify_time_claims(10, Default::default(), None, None, None).unwrap();
        // exp > now
        verify_time_claims(10, Default::default(), None, Some(20), None).unwrap();
        // exp == now
        verify_time_claims(10, Default::default(), None, Some(10), None).unwrap();
        // exp == now -leeway
        verify_time_claims(10, Duration::from_secs(5), None, Some(5), None).unwrap();
        // exp > now - leeway
        assert!(matches!(verify_time_claims(10, Duration::from_secs(5), None, Some(4), None), Err(CwtTimeError::Expired)));
    }

    #[test]
    fn nbf() {
        // no nbf verification
        verify_time_claims(10, Default::default(), None, None, None).unwrap();
        // nbf < now
        verify_time_claims(10, Default::default(), None, None, Some(5)).unwrap();
        // nbf == now
        verify_time_claims(10, Default::default(), None, None, Some(10)).unwrap();
        // nbf == now + leeway
        verify_time_claims(10, Duration::from_secs(5), None, None, Some(15)).unwrap();
        // nbf > now + leeway
        assert!(matches!(
            verify_time_claims(10, Duration::from_secs(5), None, None, Some(16)),
            Err(CwtTimeError::NotValidYet)
        ));
    }
}
