use crate::lookup::TokenQuery;
use ciborium::Value;
use coset::iana::CwtClaimName;
use esdicawt_spec::{
    CustomClaims, Select,
    issuance::SdCwtIssuedTagged,
    key_binding::KbtCwtTagged,
    reexports::{coset, coset::iana::EnumI64},
};
use std::borrow::Cow;

#[allow(dead_code)]
pub trait SdCwtRead: TokenQuery {
    type PayloadClaims: CustomClaims;

    fn sub(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtClaimName::Sub.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn iss(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtClaimName::Iss.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn aud(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtClaimName::Aud.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn exp(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CwtClaimName::Exp.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn nbf(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CwtClaimName::Nbf.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn iat(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CwtClaimName::Iat.to_i64().into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }
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
    CustomError(#[from] Box<dyn core::error::Error + Send + Sync>),
}

impl<IssuerPayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims> SdCwtRead
    for SdCwtIssuedTagged<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
{
    type PayloadClaims = IssuerPayloadClaims;

    // sub is not redactable so we read it directly from the SD-CWT
    fn sub(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.0.payload.to_value()?.inner.subject.as_deref().map(Cow::Borrowed))
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    KbtPayloadClaims: CustomClaims,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
> SdCwtRead for KbtCwtTagged<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
{
    type PayloadClaims = IssuerPayloadClaims;
}
