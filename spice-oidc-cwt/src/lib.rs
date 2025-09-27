use esdicawt::{
    EsdicawtReadResult, TokenQuery,
    spec::{
        ClaimName, CustomClaims, Select, Value,
        issuance::{SdCwtIssued, SdCwtIssuedTagged},
        key_binding::{KbtCwt, KbtCwtTagged},
    },
};
use serde::ser::SerializeMap;
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

pub const CWT_CLAIM_ADDRESS_FORMATTED: i64 = 1;
pub const CWT_CLAIM_ADDRESS_STREET_ADDRESS: i64 = 2;
pub const CWT_CLAIM_ADDRESS_LOCALITY: i64 = 3;
pub const CWT_CLAIM_ADDRESS_REGION: i64 = 4;
pub const CWT_CLAIM_ADDRESS_POSTAL_CODE: i64 = 5;
pub const CWT_CLAIM_ADDRESS_COUNTRY: i64 = 6;

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

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
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

impl serde::Serialize for SpiceOidcClaims {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Some(name) = &self.name {
            map.serialize_entry(&CWT_CLAIM_NAME, name)?;
        }
        if let Some(given_name) = &self.given_name {
            map.serialize_entry(&CWT_CLAIM_GIVEN_NAME, given_name)?;
        }
        if let Some(family_name) = &self.family_name {
            map.serialize_entry(&CWT_CLAIM_FAMILY_NAME, family_name)?;
        }
        if let Some(middle_name) = &self.middle_name {
            map.serialize_entry(&CWT_CLAIM_MIDDLE_NAME, middle_name)?;
        }
        if let Some(nickname) = &self.nickname {
            map.serialize_entry(&CWT_CLAIM_NICKNAME, nickname)?;
        }
        if let Some(preferred_username) = &self.preferred_username {
            map.serialize_entry(&CWT_CLAIM_PREFERRED_USERNAME, preferred_username)?;
        }
        if let Some(profile) = &self.profile {
            map.serialize_entry(&CWT_CLAIM_PROFILE, profile.as_str())?;
        }
        if let Some(picture) = &self.picture {
            map.serialize_entry(&CWT_CLAIM_PICTURE, picture.as_str())?;
        }
        if let Some(website) = &self.website {
            map.serialize_entry(&CWT_CLAIM_WEBSITE, website.as_str())?;
        }
        if let Some(email) = &self.email {
            map.serialize_entry(&CWT_CLAIM_EMAIL, email)?;
        }
        if let Some(email_verified) = &self.email_verified {
            map.serialize_entry(&CWT_CLAIM_EMAIL_VERIFIED, email_verified)?;
        }
        if let Some(gender) = &self.gender {
            map.serialize_entry(&CWT_CLAIM_GENDER, gender)?;
        }
        if let Some(birthdate) = &self.birthdate {
            map.serialize_entry(&CWT_CLAIM_BIRTHDATE, birthdate)?;
        }
        if let Some(zoneinfo) = &self.zoneinfo {
            map.serialize_entry(&CWT_CLAIM_ZONEINFO, zoneinfo)?;
        }
        if let Some(locale) = &self.locale {
            map.serialize_entry(&CWT_CLAIM_LOCALE, locale)?;
        }
        if let Some(phone_number) = &self.phone_number {
            map.serialize_entry(&CWT_CLAIM_PHONE_NUMBER, phone_number)?;
        }
        if let Some(phone_number_verified) = &self.phone_number_verified {
            map.serialize_entry(&CWT_CLAIM_PHONE_NUMBER_VERIFIED, phone_number_verified)?;
        }
        if let Some(address) = &self.address {
            if let Ok(address_json) = serde_json::to_string(&address) {
                map.serialize_entry(&CWT_CLAIM_ADDRESS, &address_json)?;
            }
        }
        if let Some(updated_at) = &self.updated_at {
            map.serialize_entry(&CWT_CLAIM_UPDATED_AT, updated_at)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for SpiceOidcClaims {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SpiceOidcClaimsVisitor;

        impl<'de> serde::de::Visitor<'de> for SpiceOidcClaimsVisitor {
            type Value = SpiceOidcClaims;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an OIDC payload")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let mut oidc = SpiceOidcClaims::default();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match (k, v) {
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_NAME.into() => {
                            oidc.name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_GIVEN_NAME.into() => {
                            oidc.given_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_FAMILY_NAME.into() => {
                            oidc.family_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_MIDDLE_NAME.into() => {
                            oidc.middle_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_NICKNAME.into() => {
                            oidc.nickname.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_PREFERRED_USERNAME.into() => {
                            oidc.preferred_username.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_PROFILE.into() => {
                            oidc.profile.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_PICTURE.into() => {
                            oidc.picture.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_WEBSITE.into() => {
                            oidc.website.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_EMAIL.into() => {
                            oidc.email.replace(s);
                        }
                        (Value::Integer(i), Value::Bool(b)) if i == CWT_CLAIM_EMAIL_VERIFIED.into() => {
                            oidc.email_verified.replace(b);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_GENDER.into() => {
                            oidc.gender.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_BIRTHDATE.into() => {
                            oidc.birthdate.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ZONEINFO.into() => {
                            oidc.zoneinfo.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_LOCALE.into() => {
                            oidc.locale.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_PHONE_NUMBER.into() => {
                            oidc.phone_number.replace(s);
                        }
                        (Value::Integer(i), Value::Bool(b)) if i == CWT_CLAIM_PHONE_NUMBER_VERIFIED.into() => {
                            oidc.phone_number_verified.replace(b);
                        }
                        (Value::Integer(i), value @ Value::Map(_)) if i == CWT_CLAIM_ADDRESS.into() => {
                            oidc.address.replace(Value::deserialized(&value).map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Integer(u)) if i == CWT_CLAIM_UPDATED_AT.into() => {
                            oidc.updated_at.replace(u.try_into().map_err(A::Error::custom)?);
                        }
                        _ => {}
                    }
                }

                Ok(oidc)
            }
        }

        deserializer.deserialize_map(SpiceOidcClaimsVisitor)
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

#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct OidcAddressClaim {
    pub formatted: Option<String>,
    pub street_address: Option<String>,
    pub locality: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
}

impl serde::Serialize for OidcAddressClaim {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        if let Some(formatted) = &self.formatted {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_FORMATTED, formatted)?;
        }
        if let Some(street_address) = &self.street_address {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_STREET_ADDRESS, street_address)?;
        }
        if let Some(locality) = &self.locality {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_LOCALITY, locality)?;
        }
        if let Some(region) = &self.region {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_REGION, region)?;
        }
        if let Some(postal_code) = &self.postal_code {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_POSTAL_CODE, postal_code)?;
        }
        if let Some(country) = &self.country {
            map.serialize_entry(&CWT_CLAIM_ADDRESS_COUNTRY, country)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for OidcAddressClaim {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OidcAddressClaimVisitor;

        impl<'de> serde::de::Visitor<'de> for OidcAddressClaimVisitor {
            type Value = OidcAddressClaim;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an address")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut address = OidcAddressClaim::default();
                while let Some((k, v)) = map.next_entry::<Value, Value>()? {
                    match (k, v) {
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_FORMATTED.into() => {
                            address.formatted.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_STREET_ADDRESS.into() => {
                            address.street_address.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_LOCALITY.into() => {
                            address.locality.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_REGION.into() => {
                            address.region.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_POSTAL_CODE.into() => {
                            address.postal_code.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CWT_CLAIM_ADDRESS_COUNTRY.into() => {
                            address.country.replace(s);
                        }
                        _ => {}
                    }
                }

                Ok(address)
            }
        }

        deserializer.deserialize_map(OidcAddressClaimVisitor)
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

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims> SpiceOidcSdCwtRead
    for SdCwtIssued<PayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
where
    for<'a> &'a PayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_GIVEN_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_FAMILY_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_MIDDLE_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_NICKNAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self
            .query(vec![CWT_CLAIM_PREFERRED_USERNAME.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_PROFILE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_PICTURE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_WEBSITE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_EMAIL.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self.query(vec![CWT_CLAIM_EMAIL_VERIFIED.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_GENDER.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_BIRTHDATE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_ZONEINFO.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_LOCALE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_PHONE_NUMBER.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .query(vec![CWT_CLAIM_PHONE_NUMBER_VERIFIED.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self.query(vec![CWT_CLAIM_ADDRESS.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CWT_CLAIM_UPDATED_AT.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }
}

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims> SpiceOidcSdCwtRead
    for SdCwtIssuedTagged<PayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
where
    for<'a> &'a PayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.name()
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.given_name()
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.family_name()
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.middle_name()
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.nickname()
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.preferred_username()
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.profile()
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.picture()
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.website()
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.email()
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.email_verified()
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.gender()
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.birthdate()
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.zoneinfo()
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.locale()
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.phone_number()
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.phone_number_verified()
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        self.0.address()
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.0.updated_at()
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> SpiceOidcSdCwtRead for KbtCwt<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims>
where
    for<'a> &'a IssuerPayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_GIVEN_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_FAMILY_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_MIDDLE_NAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_NICKNAME.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self
            .query(vec![CWT_CLAIM_PREFERRED_USERNAME.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_PROFILE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_PICTURE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CWT_CLAIM_WEBSITE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_EMAIL.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self.query(vec![CWT_CLAIM_EMAIL_VERIFIED.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_GENDER.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_BIRTHDATE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_ZONEINFO.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_LOCALE.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CWT_CLAIM_PHONE_NUMBER.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .query(vec![CWT_CLAIM_PHONE_NUMBER_VERIFIED.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self.query(vec![CWT_CLAIM_ADDRESS.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CWT_CLAIM_UPDATED_AT.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }
}

impl<
    IssuerPayloadClaims: Select,
    Hasher: digest::Digest + Clone,
    IssuerProtectedClaims: CustomClaims,
    IssuerUnprotectedClaims: CustomClaims,
    KbtProtectedClaims: CustomClaims,
    KbtUnprotectedClaims: CustomClaims,
    KbtPayloadClaims: CustomClaims,
> SpiceOidcSdCwtRead for KbtCwtTagged<IssuerPayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims, KbtPayloadClaims>
where
    for<'a> &'a IssuerPayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.name()
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.given_name()
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.family_name()
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.middle_name()
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.nickname()
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.preferred_username()
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.profile()
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.picture()
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.website()
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.email()
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.email_verified()
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.gender()
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.birthdate()
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.zoneinfo()
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.locale()
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.phone_number()
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.phone_number_verified()
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        self.0.address()
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.0.updated_at()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ed25519::*, *};
    use esdicawt::{
        CborPath, Holder, Issuer, Presentation,
        spec::{CwtAny, issuance::SdCwtIssuedTagged},
    };

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

        let presentation = Presentation::Path(Box::new(|path| {
            matches!(
                path,
                [CborPath::Int(CWT_CLAIM_NAME), ..]
                    | [CborPath::Int(CWT_CLAIM_GIVEN_NAME), ..]
                    | [CborPath::Int(CWT_CLAIM_FAMILY_NAME), ..]
                    | [CborPath::Int(CWT_CLAIM_NICKNAME), ..]
                    | [CborPath::Int(CWT_CLAIM_PREFERRED_USERNAME), ..]
            )
        }));
        let mut alice_kbt = alice_holder
            .new_presentation(
                &alice_sd_cwt.to_cbor_bytes().unwrap(),
                esdicawt::HolderParams {
                    presentation,
                    audience: "bob",
                    expiry: Some(Duration::from_secs(86400)),
                    with_not_before: false,
                    leeway: Duration::from_secs(100),
                    extra_kbt_unprotected: None,
                    extra_kbt_protected: None,
                    extra_kbt_payload: None,
                    now: None,
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
    ) -> SdCwtIssuedTagged<SpiceOidcClaims, sha2::Sha256> {
        issuer
            .issue_cwt(
                &mut rand::thread_rng(),
                esdicawt::IssuerParams {
                    protected_claims: None,
                    unprotected_claims: None,
                    payload: Some(claims),
                    subject: Some(subject),
                    audience: Default::default(),
                    cti: Default::default(),
                    cnonce: Default::default(),
                    issuer: "",
                    expiry: Some(Duration::from_secs(90)),
                    with_not_before: false,
                    leeway: Duration::from_secs(1),
                    key_location: "",
                    holder_confirmation_key: holder_pk.try_into().unwrap(),
                    now: None,
                    with_issued_at: false,
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

    impl Select for SpiceOidcClaims {}
}

#[cfg(test)]
mod ed25519 {
    use crate::SpiceOidcClaims;
    use esdicawt::{
        Holder, Issuer,
        spec::{NoClaims, SdHashAlg, reexports::coset},
    };
    use esdicawt_spec::EsdicawtSpecError;

    pub struct Ed25519Issuer {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl Issuer for Ed25519Issuer {
        type Error = EsdicawtSpecError;
        type Signer = ed25519_dalek::SigningKey;
        type Hasher = sha2::Sha256;
        type Signature = ed25519_dalek::Signature;

        type ProtectedClaims = NoClaims;
        type UnprotectedClaims = NoClaims;
        type PayloadClaims = SpiceOidcClaims;

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
        type Hasher = sha2::Sha256;

        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = SpiceOidcClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;
        type KbtPayloadClaims = NoClaims;

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
    }
}
