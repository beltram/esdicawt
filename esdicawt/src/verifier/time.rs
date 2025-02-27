use crate::verifier::error::SdCwtVerifierError;

pub fn verify_time_claims<E: std::error::Error + Send + Sync>(now: i64, leeway: i64, iat: Option<i64>, exp: Option<i64>, nbf: Option<i64>) -> Result<(), SdCwtVerifierError<E>> {
    if let Some(iat) = iat {
        if iat > now.saturating_add(leeway) {
            return Err(SdCwtVerifierError::ClockDrift);
        }
    }
    if let Some(exp) = exp {
        if now.saturating_sub(leeway) > exp {
            return Err(SdCwtVerifierError::Expired);
        }
    }
    if let Some(nbf) = nbf {
        if now.saturating_add(leeway) < nbf {
            return Err(SdCwtVerifierError::NotValidYet);
        }
    }
    Ok(())
}
