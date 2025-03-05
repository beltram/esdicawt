use ciborium::Value;
use coset::iana::CwtClaimName;
use esdicawt_spec::{
    ClaimName, CustomClaims, Select,
    blinded_claims::{Salted, SaltedClaim},
    issuance::{SdCwtIssuedTagged, SdInnerPayload},
    key_binding::KbtCwtTagged,
    reexports::{coset, coset::iana::EnumI64},
};
use std::borrow::Cow;

#[allow(dead_code)]
pub trait SdCwtRead {
    type PayloadClaims: CustomClaims;

    // TODO: pending optional vs mandatory claims is settled. tl;dr: it should be required
    fn iss(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CwtClaimName::Iss.to_i64().into(), |payload| Some(&*payload.issuer))
    }

    fn sub(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CwtClaimName::Sub.to_i64().into(), |payload| payload.subject.as_deref())
    }

    fn aud(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CwtClaimName::Aud.to_i64().into(), |payload| payload.audience.as_deref())
    }

    fn exp(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.maybe_std_int_claim(CwtClaimName::Exp.to_i64().into(), |payload| payload.expiration)
    }

    fn nbf(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.maybe_std_int_claim(CwtClaimName::Nbf.to_i64().into(), |payload| payload.not_before)
    }

    fn iat(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.maybe_std_int_claim(CwtClaimName::Iat.to_i64().into(), |payload| payload.issued_at)
    }

    fn maybe_std_claim<'a, T: serde::Serialize + 'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a T>,
    ) -> EsdicawtReadResult<Option<Value>>;

    fn maybe_std_str_claim<'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a str>,
    ) -> EsdicawtReadResult<Option<Cow<'a, str>>>;

    fn maybe_std_int_claim<'a>(&'a mut self, key: ClaimName, extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<i64>) -> EsdicawtReadResult<Option<i64>>;
}

pub type EsdicawtReadResult<T> = Result<T, EsdicawtReadError>;

#[derive(Debug, thiserror::Error)]
pub enum EsdicawtReadError {
    #[error(transparent)]
    SpecError(#[from] esdicawt_spec::EsdicawtSpecError),
    #[error(transparent)]
    CborValueError(#[from] ciborium::value::Error),
    #[error(transparent)]
    CborIntError(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    CustomError(#[from] Box<dyn std::error::Error + Send + Sync>),
}

impl<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, IssuerPayloadClaims: Select> SdCwtRead
    for SdCwtIssuedTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims>
{
    type PayloadClaims = IssuerPayloadClaims;

    fn maybe_std_claim<'a, T: serde::Serialize + 'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a T>,
    ) -> EsdicawtReadResult<Option<Value>> {
        let payload = self.0.payload.to_value()?;
        let unredacted = extractor(&payload.inner);
        let unredacted = unredacted.as_ref().map(Value::serialized).transpose()?;

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = self.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures.iter().find_map(|s| match s {
                Ok(Salted::Claim(SaltedClaim { name, value, .. })) if name == key => Some(value),
                _ => None,
            });
            Ok(redacted)
        }
    }

    fn maybe_std_str_claim<'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a str>,
    ) -> EsdicawtReadResult<Option<Cow<'a, str>>> {
        let payload = self.0.payload.to_value()?;
        let unredacted = extractor(&payload.inner).map(Cow::Borrowed);

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = self.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures
                .iter()
                .find_map(|s| match s {
                    Ok(Salted::Claim(SaltedClaim { name, value: Value::Text(v), .. })) if name == key => Some(v),
                    _ => None,
                })
                .map(Cow::Owned);
            Ok(redacted)
        }
    }

    fn maybe_std_int_claim<'a>(&'a mut self, key: ClaimName, extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<i64>) -> EsdicawtReadResult<Option<i64>> {
        let payload = self.0.payload.to_value()?;
        let unredacted = extractor(&payload.inner);

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = self.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures
                .iter()
                .find_map(|s| match s {
                    Ok(Salted::Claim(SaltedClaim {
                        name, value: Value::Integer(v), ..
                    })) if name == key => Some(v.try_into()),
                    _ => None,
                })
                .transpose()?;
            Ok(redacted)
        }
    }
}

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    IssuerPayloadClaims: Select,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> SdCwtRead for KbtCwtTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, IssuerPayloadClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims>
{
    type PayloadClaims = IssuerPayloadClaims;

    fn maybe_std_claim<'a, T: serde::Serialize + 'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a T>,
    ) -> EsdicawtReadResult<Option<Value>> {
        let protected = self.0.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let unredacted = extractor(&sd_cwt_payload.inner);
        let unredacted = unredacted.as_ref().map(Value::serialized).transpose()?;

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = sd_cwt.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures.iter().find_map(|s| match s {
                Ok(Salted::Claim(SaltedClaim { name, value, .. })) if name == key => Some(value),
                _ => None,
            });
            Ok(redacted)
        }
    }

    fn maybe_std_str_claim<'a>(
        &'a mut self,
        key: ClaimName,
        extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<&'a str>,
    ) -> EsdicawtReadResult<Option<Cow<'a, str>>> {
        let protected = self.0.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let unredacted = extractor(&sd_cwt_payload.inner).map(Cow::Borrowed);

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = sd_cwt.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures
                .iter()
                .find_map(|s| match s {
                    Ok(Salted::Claim(SaltedClaim { name, value: Value::Text(v), .. })) if name == key => Some(v),
                    _ => None,
                })
                .map(Cow::Owned);
            Ok(redacted)
        }
    }

    fn maybe_std_int_claim<'a>(&'a mut self, key: ClaimName, extractor: impl FnOnce(&'a SdInnerPayload<Self::PayloadClaims>) -> Option<i64>) -> EsdicawtReadResult<Option<i64>> {
        let protected = self.0.protected.to_value_mut()?;
        let sd_cwt = protected.kcwt.to_value_mut()?;
        let sd_cwt_payload = sd_cwt.0.payload.to_value_mut()?;
        let unredacted = extractor(&sd_cwt_payload.inner);

        if let Some(claim) = unredacted {
            Ok(Some(claim))
        } else {
            let disclosures = sd_cwt.0.sd_unprotected.sd_claims.to_value()?;
            let redacted = disclosures
                .iter()
                .find_map(|s| match s {
                    Ok(Salted::Claim(SaltedClaim {
                        name, value: Value::Integer(v), ..
                    })) if name == key => Some(v.try_into()),
                    _ => None,
                })
                .transpose()?;
            Ok(redacted)
        }
    }
}
