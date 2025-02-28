use esdicawt::{
    EsdicawtReadError, EsdicawtReadResult, SdCwtRead,
    spec::{AnyMap, CustomClaims, issuance::SdCwtIssuedTagged, key_binding::KbtCwtTagged},
};
use esdicawt_spec::{ClaimName, Value};
use std::{borrow::Cow, collections::HashMap, sync::LazyLock};
use url::Url;

pub const CWT_CLAIM_NAME: i64 = 170;
pub const CWT_CLAIM_GIVEN_NAME: i64 = 171;
pub const CWT_CLAIM_FAMILY_NAME: i64 = 172;
pub const CWT_CLAIM_MIDDLE_NAME: i64 = 173;
pub const CWT_CLAIM_NICKNAME: i64 = 174;
pub const CWT_CLAIM_PREFERRED_USERNAME: i64 = 175;
pub const CWT_CLAIM_PROFILE: i64 = 176;
pub const CWT_CLAIM_PICTURE: i64 = 177;
pub const CWT_CLAIM_WEBSITE: i64 = 178;
pub const CWT_CLAIM_EMAIL: i64 = 179;
pub const CWT_CLAIM_EMAIL_VERIFIED: i64 = 180;
pub const CWT_CLAIM_GENDER: i64 = 181;
pub const CWT_CLAIM_BIRTHDATE: i64 = 182;
pub const CWT_CLAIM_ZONEINFO: i64 = 183;
pub const CWT_CLAIM_LOCALE: i64 = 184;
pub const CWT_CLAIM_PHONE_NUMBER: i64 = 185;
pub const CWT_CLAIM_PHONE_NUMBER_VERIFIED: i64 = 186;
pub const CWT_CLAIM_ADDRESS: i64 = 187;
pub const CWT_CLAIM_UPDATED_AT: i64 = 188;

pub const OIDC_NAME: &str = "name";
pub const OIDC_GIVEN_NAME: &str = "given_name";
pub const OIDC_FAMILY_NAME: &str = "family_name";
pub const OIDC_MIDDLE_NAME: &str = "middle_name";
pub const OIDC_NICKNAME: &str = "nickname";
pub const OIDC_PREFERRED_USERNAME: &str = "preferred_username";
pub const OIDC_PROFILE: &str = "profile";
pub const OIDC_PICTURE: &str = "picture";
pub const OIDC_WEBSITE: &str = "website";
pub const OIDC_EMAIL: &str = "email";
pub const OIDC_EMAIL_VERIFIED: &str = "email_verified";
pub const OIDC_GENDER: &str = "gender";
pub const OIDC_BIRTHDATE: &str = "birthdate";
pub const OIDC_ZONEINFO: &str = "zoneinfo";
pub const OIDC_LOCALE: &str = "locale";
pub const OIDC_PHONE_NUMBER: &str = "phone_number";
pub const OIDC_PHONE_NUMBER_VERIFIED: &str = "phone_number_verified";
pub const OIDC_ADDRESS: &str = "address";
pub const OIDC_UPDATED_AT: &str = "updated_at";

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct OidcAddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(from = "AnyMap", into = "AnyMap")]
pub struct SpiceOidcClaims {
    pub name: Option<String>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub middle_name: Option<String>,
    pub nickname: Option<String>,
    pub preferred_username: Option<String>,
    pub profile: Option<Url>,
    pub picture: Option<Url>,
    pub website: Option<Url>,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub gender: Option<String>,
    pub birthdate: Option<String>,
    pub zoneinfo: Option<String>,
    pub locale: Option<String>,
    pub phone_number: Option<String>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<OidcAddressClaim>,
    pub updated_at: Option<u64>,
}

impl From<SpiceOidcClaims> for AnyMap {
    fn from(val: SpiceOidcClaims) -> Self {
        let mut anymap = Self::default();
        if let Some(name) = val.name {
            anymap.insert(CWT_CLAIM_NAME.into(), name.into());
        }
        if let Some(given_name) = val.given_name {
            anymap.insert(CWT_CLAIM_GIVEN_NAME.into(), given_name.into());
        }
        if let Some(family_name) = val.family_name {
            anymap.insert(CWT_CLAIM_FAMILY_NAME.into(), family_name.into());
        }
        if let Some(middle_name) = val.middle_name {
            anymap.insert(CWT_CLAIM_MIDDLE_NAME.into(), middle_name.into());
        }
        if let Some(nickname) = val.nickname {
            anymap.insert(CWT_CLAIM_NICKNAME.into(), nickname.into());
        }
        if let Some(preferred_username) = val.preferred_username {
            anymap.insert(CWT_CLAIM_PREFERRED_USERNAME.into(), preferred_username.into());
        }
        if let Some(profile) = val.profile {
            let s: String = profile.into();
            anymap.insert(CWT_CLAIM_PROFILE.into(), s.into());
        }
        if let Some(picture) = val.picture {
            let s: String = picture.into();
            anymap.insert(CWT_CLAIM_PICTURE.into(), s.into());
        }
        if let Some(website) = val.website {
            let s: String = website.into();
            anymap.insert(CWT_CLAIM_WEBSITE.into(), s.into());
        }
        if let Some(email) = val.email {
            anymap.insert(CWT_CLAIM_EMAIL.into(), email.into());
        }
        if let Some(email_verified) = val.email_verified {
            anymap.insert(CWT_CLAIM_EMAIL_VERIFIED.into(), email_verified.into());
        }
        if let Some(gender) = val.gender {
            anymap.insert(CWT_CLAIM_GENDER.into(), gender.into());
        }
        if let Some(birthdate) = val.birthdate {
            anymap.insert(CWT_CLAIM_BIRTHDATE.into(), birthdate.into());
        }
        if let Some(zoneinfo) = val.zoneinfo {
            anymap.insert(CWT_CLAIM_ZONEINFO.into(), zoneinfo.into());
        }
        if let Some(locale) = val.locale {
            anymap.insert(CWT_CLAIM_LOCALE.into(), locale.into());
        }
        if let Some(phone_number) = val.phone_number {
            anymap.insert(CWT_CLAIM_PHONE_NUMBER.into(), phone_number.into());
        }
        if let Some(phone_number_verified) = val.phone_number_verified {
            anymap.insert(CWT_CLAIM_PHONE_NUMBER_VERIFIED.into(), phone_number_verified.into());
        }
        if let Some(address) = val.address {
            if let Ok(address_json) = serde_json::to_string(&address) {
                anymap.insert(CWT_CLAIM_ADDRESS.into(), address_json.into());
            }
        }
        if let Some(updated_at) = val.updated_at {
            anymap.insert(CWT_CLAIM_UPDATED_AT.into(), updated_at.into());
        }

        anymap
    }
}

impl From<AnyMap> for SpiceOidcClaims {
    fn from(mut map: AnyMap) -> Self {
        let mut value = Self::default();
        if let Some(name) = map.remove(&CWT_CLAIM_NAME.into()) {
            value.name = name.into_text().ok();
        }
        if let Some(given_name) = map.remove(&CWT_CLAIM_GIVEN_NAME.into()) {
            value.given_name = given_name.into_text().ok();
        }
        if let Some(family_name) = map.remove(&CWT_CLAIM_FAMILY_NAME.into()) {
            value.family_name = family_name.into_text().ok();
        }
        if let Some(middle_name) = map.remove(&CWT_CLAIM_MIDDLE_NAME.into()) {
            value.middle_name = middle_name.into_text().ok();
        }
        if let Some(nickname) = map.remove(&CWT_CLAIM_NICKNAME.into()) {
            value.nickname = nickname.into_text().ok();
        }
        if let Some(preferred_username) = map.remove(&CWT_CLAIM_PREFERRED_USERNAME.into()) {
            value.preferred_username = preferred_username.into_text().ok();
        }
        if let Some(profile) = map.remove(&CWT_CLAIM_PROFILE.into()) {
            value.profile = profile.deserialized().ok();
        }
        if let Some(picture) = map.remove(&CWT_CLAIM_PICTURE.into()) {
            value.picture = picture.deserialized().ok();
        }
        if let Some(website) = map.remove(&CWT_CLAIM_WEBSITE.into()) {
            value.website = website.deserialized().ok();
        }
        if let Some(email) = map.remove(&CWT_CLAIM_EMAIL.into()) {
            value.email = email.into_text().ok();
        }
        if let Some(email_verified) = map.remove(&CWT_CLAIM_EMAIL_VERIFIED.into()) {
            value.email_verified.replace(email_verified.into_bool().unwrap_or_default());
        }
        if let Some(gender) = map.remove(&CWT_CLAIM_GENDER.into()) {
            value.gender = gender.deserialized().ok();
        }
        if let Some(birthdate) = map.remove(&CWT_CLAIM_BIRTHDATE.into()) {
            value.birthdate = birthdate.deserialized().ok();
        }
        if let Some(zoneinfo) = map.remove(&CWT_CLAIM_ZONEINFO.into()) {
            value.zoneinfo = zoneinfo.deserialized().ok();
        }
        if let Some(locale) = map.remove(&CWT_CLAIM_LOCALE.into()) {
            value.locale = locale.deserialized().ok();
        }
        if let Some(phone_number) = map.remove(&CWT_CLAIM_PHONE_NUMBER.into()) {
            value.phone_number = phone_number.deserialized().ok();
        }
        if let Some(phone_number_verified) = map.remove(&CWT_CLAIM_PHONE_NUMBER_VERIFIED.into()) {
            value.phone_number_verified.replace(phone_number_verified.into_bool().unwrap_or_default());
        }
        if let Some(address) = map.remove(&CWT_CLAIM_ADDRESS.into()) {
            if let Some(address_struct) = address.into_text().ok().and_then(|address_str| serde_json::from_str(&address_str).ok()) {
                value.address.replace(address_struct);
            }
        }
        if let Some(updated_at) = map.remove(&CWT_CLAIM_UPDATED_AT.into()) {
            value.updated_at = updated_at.deserialized().ok();
        }

        value
    }
}

pub(crate) static CLAIM_MAP: LazyLock<HashMap<&'static str, ClaimName>> = LazyLock::new(|| {
    [
        (OIDC_NAME, CWT_CLAIM_NAME.into()),
        (OIDC_GIVEN_NAME, CWT_CLAIM_GIVEN_NAME.into()),
        (OIDC_FAMILY_NAME, CWT_CLAIM_FAMILY_NAME.into()),
        (OIDC_MIDDLE_NAME, CWT_CLAIM_MIDDLE_NAME.into()),
        (OIDC_NAME, CWT_CLAIM_NICKNAME.into()),
        (OIDC_PREFERRED_USERNAME, CWT_CLAIM_PREFERRED_USERNAME.into()),
        (OIDC_PROFILE, CWT_CLAIM_PROFILE.into()),
        (OIDC_PICTURE, CWT_CLAIM_PICTURE.into()),
        (OIDC_WEBSITE, CWT_CLAIM_WEBSITE.into()),
        (OIDC_EMAIL, CWT_CLAIM_EMAIL.into()),
        (OIDC_EMAIL_VERIFIED, CWT_CLAIM_EMAIL_VERIFIED.into()),
        (OIDC_GENDER, CWT_CLAIM_GENDER.into()),
        (OIDC_BIRTHDATE, CWT_CLAIM_BIRTHDATE.into()),
        (OIDC_ZONEINFO, CWT_CLAIM_ZONEINFO.into()),
        (OIDC_LOCALE, CWT_CLAIM_LOCALE.into()),
        (OIDC_PHONE_NUMBER, CWT_CLAIM_PHONE_NUMBER.into()),
        (OIDC_PHONE_NUMBER_VERIFIED, CWT_CLAIM_PHONE_NUMBER_VERIFIED.into()),
        (OIDC_ADDRESS, CWT_CLAIM_ADDRESS.into()),
        (OIDC_UPDATED_AT, CWT_CLAIM_UPDATED_AT.into()),
    ]
    .into_iter()
    .collect()
});

impl SpiceOidcClaims {
    pub fn claim_name(name: &str) -> Option<&ClaimName> {
        (*CLAIM_MAP).get(name)
    }
}

pub trait SpiceOidcSdCwtRead {
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>>;
    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>>;
    fn website(&mut self) -> EsdicawtReadResult<Option<Url>>;
    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>>;
    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>>;
    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>>;
    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>>;
    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>>;
}

impl<IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims, PayloadClaims: CustomClaims, DisclosableClaims: CustomClaims> SpiceOidcSdCwtRead
    for SdCwtIssuedTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, DisclosableClaims>
where
    for<'a> &'a PayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().name.as_deref()))
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_GIVEN_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().given_name.as_deref()))
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_FAMILY_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().family_name.as_deref()))
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_MIDDLE_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().middle_name.as_deref()))
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_NICKNAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().nickname.as_deref()))
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_PREFERRED_USERNAME.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().preferred_username.as_deref())
        })
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_PROFILE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().profile.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_PICTURE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().picture.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_WEBSITE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().website.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_EMAIL.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().email.as_deref()))
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_EMAIL_VERIFIED.into(), |payload| {
                payload.extra.as_ref().and_then(|c| c.into().email_verified.as_ref())
            })?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_GENDER.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().gender.as_deref()))
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_BIRTHDATE.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().birthdate.as_deref()))
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_ZONEINFO.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().zoneinfo.as_deref()))
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_LOCALE.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().locale.as_deref()))
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_PHONE_NUMBER.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().phone_number.as_deref())
        })
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_PHONE_NUMBER_VERIFIED.into(), |payload| {
                payload.extra.as_ref().and_then(|c| c.into().phone_number_verified.as_ref())
            })?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_ADDRESS.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().address.as_ref()))?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_UPDATED_AT.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().updated_at.as_ref()))?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }
}

impl<
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    PayloadClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> SpiceOidcSdCwtRead for KbtCwtTagged<IssuerProtectedClaims, IssuerUnprotectedClaims, PayloadClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims, PayloadClaims>
where
    for<'a> &'a PayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().name.as_deref()))
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_GIVEN_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().given_name.as_deref()))
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_FAMILY_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().family_name.as_deref()))
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_MIDDLE_NAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().middle_name.as_deref()))
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_NICKNAME.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().nickname.as_deref()))
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_PREFERRED_USERNAME.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().preferred_username.as_deref())
        })
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_PROFILE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().profile.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_PICTURE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().picture.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.maybe_std_str_claim(CWT_CLAIM_WEBSITE.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().website.as_ref()).map(|p| p.as_str())
        })?
        .map(|u| u.as_ref().parse())
        .transpose()
        .map_err(|e| EsdicawtReadError::CustomError(Box::new(e)))
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_EMAIL.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().email.as_deref()))
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_EMAIL_VERIFIED.into(), |payload| {
                payload.extra.as_ref().and_then(|c| c.into().email_verified.as_ref())
            })?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_GENDER.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().gender.as_deref()))
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_BIRTHDATE.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().birthdate.as_deref()))
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_ZONEINFO.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().zoneinfo.as_deref()))
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_LOCALE.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().locale.as_deref()))
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.maybe_std_str_claim(CWT_CLAIM_PHONE_NUMBER.into(), |payload| {
            payload.extra.as_ref().and_then(|c| c.into().phone_number.as_deref())
        })
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_PHONE_NUMBER_VERIFIED.into(), |payload| {
                payload.extra.as_ref().and_then(|c| c.into().phone_number_verified.as_ref())
            })?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_ADDRESS.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().address.as_ref()))?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self
            .maybe_std_claim(CWT_CLAIM_UPDATED_AT.into(), |payload| payload.extra.as_ref().and_then(|c| c.into().updated_at.as_ref()))?
            .map(|b| Value::deserialized(&b))
            .transpose()?)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ed25519::*, *};
    use esdicawt::{
        Holder, Issuer, Presentation,
        spec::{CwtAny, issuance::SdCwtIssuedTagged},
    };
    use esdicawt_spec::NoClaims;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn can_issue_and_present_oidc_claim_token() {
        let issuer = Ed25519Issuer::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));
        let alice_holder = Ed25519Holder::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

        let _bob_holder = Ed25519Holder::new(ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()));

        let alice = get_alice();
        let alice_subject = alice.preferred_username.clone().unwrap();
        let mut alice_sd_cwt = issue_oidc_claim(&issuer, alice, &alice_holder.signer().verifying_key(), &alice_subject);

        let name = alice_sd_cwt.name().unwrap().unwrap().to_string();
        let given_name = alice_sd_cwt.given_name().unwrap().unwrap().to_string();
        let family_name = alice_sd_cwt.family_name().unwrap().unwrap().to_string();
        let nickname = alice_sd_cwt.nickname().unwrap().unwrap().to_string();
        let preferred_username = alice_sd_cwt.preferred_username().unwrap().unwrap().to_string();
        assert_eq!(name, "Alice".to_string());
        assert_eq!(given_name, "Alice Smith".to_string());
        assert_eq!(family_name, "Smith".to_string());
        assert_eq!(nickname, "alice".to_string());
        assert_eq!(preferred_username, "alice".to_string());

        let mut alice_kbt = alice_holder
            .new_presentation(
                &alice_sd_cwt.to_cbor_bytes().unwrap(),
                esdicawt::CwtPresentationParams {
                    presentation: Presentation::Full,
                    audience: "bob",
                    expiry: Duration::from_secs(86400),
                    leeway: Duration::from_secs(100),
                    extra_kbt_unprotected: None,
                    extra_kbt_protected: None,
                    extra_kbt_payload: None,
                },
            )
            .unwrap();

        let name = alice_kbt.name().unwrap().unwrap().to_string();
        let given_name = alice_kbt.given_name().unwrap().unwrap().to_string();
        let family_name = alice_kbt.family_name().unwrap().unwrap().to_string();
        let nickname = alice_kbt.nickname().unwrap().unwrap().to_string();
        let preferred_username = alice_kbt.preferred_username().unwrap().unwrap().to_string();
        assert_eq!(name, "Alice".to_string());
        assert_eq!(given_name, "Alice Smith".to_string());
        assert_eq!(family_name, "Smith".to_string());
        assert_eq!(nickname, "alice".to_string());
        assert_eq!(preferred_username, "alice".to_string());
    }

    fn issue_oidc_claim(
        issuer: &Ed25519Issuer,
        claims: SpiceOidcClaims,
        holder_pk: &ed25519_dalek::VerifyingKey,
        subject: &str,
    ) -> SdCwtIssuedTagged<NoClaims, NoClaims, SpiceOidcClaims, SpiceOidcClaims> {
        issuer
            .issue_cwt(
                &mut rand::thread_rng(),
                esdicawt::IssueCwtParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload_claims: None,
                    disclosable_claims: claims,
                    subject,
                    identifier: "",
                    expiry: Duration::from_secs(90),
                    leeway: Duration::from_secs(1),
                    key_location: "",
                    holder_confirmation_key: holder_pk.try_into().unwrap(),
                },
            )
            .unwrap()
    }

    fn get_alice() -> SpiceOidcClaims {
        SpiceOidcClaims {
            name: Some("Alice".into()),
            given_name: Some("Alice Smith".into()),
            family_name: Some("Smith".into()),
            nickname: Some("alice".into()),
            preferred_username: Some("alice".into()),
            ..Default::default()
        }
    }

    fn _get_bob() -> SpiceOidcClaims {
        SpiceOidcClaims {
            name: Some("Bob".into()),
            given_name: Some("Bob Martin".into()),
            family_name: Some("Martin".into()),
            nickname: Some("bob".into()),
            preferred_username: Some("bob".into()),
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod ed25519 {
    use crate::SpiceOidcClaims;
    use esdicawt::{
        Holder, Issuer,
        spec::{NoClaims, SdHashAlg, reexports::coset},
    };

    pub struct Ed25519Issuer {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl Issuer for Ed25519Issuer {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = ed25519_dalek::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = SpiceOidcClaims;
        type DisclosableClaims = SpiceOidcClaims;

        fn new(signing_key: Self::Signer) -> Self {
            Self { signing_key }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }

        fn serialize_signature(&self, signature: &ed25519_dalek::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(ed25519_dalek::Signature::to_bytes(signature).into())
        }

        fn deserialize_signature(&self, bytes: &[u8]) -> Result<ed25519_dalek::Signature, Self::Error> {
            Ok(ed25519_dalek::Signature::try_from(bytes).unwrap())
        }
    }

    pub struct Ed25519Holder {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl Holder for Ed25519Holder {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;
        type Signature = ed25519_dalek::Signature;

        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = SpiceOidcClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;
        type DisclosedClaims = SpiceOidcClaims;

        fn new(signing_key: Self::Signer) -> Self {
            Self { signing_key }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn hash_algorithm(&self) -> SdHashAlg {
            SdHashAlg::Sha256
        }

        fn serialize_signature(&self, signature: &ed25519_dalek::Signature) -> Result<Vec<u8>, Self::Error> {
            Ok(ed25519_dalek::Signature::to_bytes(signature).into())
        }

        fn hash(&self, msg: &[u8]) -> Vec<u8> {
            use sha2::digest::Digest as _;
            sha2::Sha256::digest(msg).to_vec()
        }
    }
}
