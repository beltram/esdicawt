use enum_variants_strings::EnumVariantsStrings;
use esdicawt::{
    cwt_label, spec::{
        issuance::{SdCwtIssued, SdCwtIssuedTagged}, key_binding::{KbtCwt, KbtCwtTagged}, ClaimName, CustomClaims,
        Select,
        Value,
    }, EsdicawtReadResult, SdCwtVerified,
    TokenQuery,
};
use serde::ser::SerializeMap;
use std::{borrow::Cow, collections::HashMap, sync::LazyLock};
use url::Url;

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, enum_variants_strings::EnumVariantsStrings)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum CwtOidcLabel {
    Name = 170,
    GivenName = 171,
    FamilyName = 172,
    MiddleName = 173,
    Nickname = 174,
    PreferredUsername = 175,
    Profile = 176,
    Picture = 177,
    Website = 178,
    Email = 179,
    EmailVerified = 180,
    Gender = 181,
    Birthdate = 182,
    ZoneInfo = 183,
    Locale = 184,
    PhoneNumber = 185,
    PhoneNumberVerified = 186,
    Address = 187,
    UpdatedAt = 188,
}
cwt_label!(CwtOidcLabel);

#[derive(Debug, Copy, Clone, serde_repr::Serialize_repr, serde_repr::Deserialize_repr, enum_variants_strings::EnumVariantsStrings)]
#[enum_variants_strings_transform(transform = "snake_case")]
#[repr(i64)]
pub enum CwtOidcAddressLabel {
    Formatted = 1,
    StreetAddress = 2,
    Locality = 3,
    Region = 4,
    PostalCode = 5,
    Country = 6,
}
cwt_label!(CwtOidcAddressLabel);

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
            map.serialize_entry(&CwtOidcLabel::Name, name)?;
        }
        if let Some(given_name) = &self.given_name {
            map.serialize_entry(&CwtOidcLabel::GivenName, given_name)?;
        }
        if let Some(family_name) = &self.family_name {
            map.serialize_entry(&CwtOidcLabel::FamilyName, family_name)?;
        }
        if let Some(middle_name) = &self.middle_name {
            map.serialize_entry(&CwtOidcLabel::MiddleName, middle_name)?;
        }
        if let Some(nickname) = &self.nickname {
            map.serialize_entry(&CwtOidcLabel::Nickname, nickname)?;
        }
        if let Some(preferred_username) = &self.preferred_username {
            map.serialize_entry(&CwtOidcLabel::PreferredUsername, preferred_username)?;
        }
        if let Some(profile) = &self.profile {
            map.serialize_entry(&CwtOidcLabel::Profile, profile.as_str())?;
        }
        if let Some(picture) = &self.picture {
            map.serialize_entry(&CwtOidcLabel::Picture, picture.as_str())?;
        }
        if let Some(website) = &self.website {
            map.serialize_entry(&CwtOidcLabel::Website, website.as_str())?;
        }
        if let Some(email) = &self.email {
            map.serialize_entry(&CwtOidcLabel::Email, email)?;
        }
        if let Some(email_verified) = &self.email_verified {
            map.serialize_entry(&CwtOidcLabel::EmailVerified, email_verified)?;
        }
        if let Some(gender) = &self.gender {
            map.serialize_entry(&CwtOidcLabel::Gender, gender)?;
        }
        if let Some(birthdate) = &self.birthdate {
            map.serialize_entry(&CwtOidcLabel::Birthdate, birthdate)?;
        }
        if let Some(zoneinfo) = &self.zoneinfo {
            map.serialize_entry(&CwtOidcLabel::ZoneInfo, zoneinfo)?;
        }
        if let Some(locale) = &self.locale {
            map.serialize_entry(&CwtOidcLabel::Locale, locale)?;
        }
        if let Some(phone_number) = &self.phone_number {
            map.serialize_entry(&CwtOidcLabel::PhoneNumber, phone_number)?;
        }
        if let Some(phone_number_verified) = &self.phone_number_verified {
            map.serialize_entry(&CwtOidcLabel::PhoneNumberVerified, phone_number_verified)?;
        }
        if let Some(address) = &self.address {
            if let Ok(address_json) = serde_json::to_string(&address) {
                map.serialize_entry(&CwtOidcLabel::Address, &address_json)?;
            }
        }
        if let Some(updated_at) = &self.updated_at {
            map.serialize_entry(&CwtOidcLabel::UpdatedAt, updated_at)?;
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
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Name => {
                            oidc.name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::GivenName => {
                            oidc.given_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::FamilyName => {
                            oidc.family_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::MiddleName => {
                            oidc.middle_name.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Nickname => {
                            oidc.nickname.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::PreferredUsername => {
                            oidc.preferred_username.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Profile => {
                            oidc.profile.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Picture => {
                            oidc.picture.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Website => {
                            oidc.website.replace(s.parse().map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Email => {
                            oidc.email.replace(s);
                        }
                        (Value::Integer(i), Value::Bool(b)) if i == CwtOidcLabel::EmailVerified => {
                            oidc.email_verified.replace(b);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Gender => {
                            oidc.gender.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Birthdate => {
                            oidc.birthdate.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::ZoneInfo => {
                            oidc.zoneinfo.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::Locale => {
                            oidc.locale.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcLabel::PhoneNumber => {
                            oidc.phone_number.replace(s);
                        }
                        (Value::Integer(i), Value::Bool(b)) if i == CwtOidcLabel::PhoneNumberVerified => {
                            oidc.phone_number_verified.replace(b);
                        }
                        (Value::Integer(i), value @ Value::Map(_)) if i == CwtOidcLabel::Address => {
                            oidc.address.replace(Value::deserialized(&value).map_err(A::Error::custom)?);
                        }
                        (Value::Integer(i), Value::Integer(u)) if i == CwtOidcLabel::UpdatedAt => {
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
        (CwtOidcLabel::Name.to_str(), CwtOidcLabel::Name.into()),
        (CwtOidcLabel::GivenName.to_str(), CwtOidcLabel::GivenName.into()),
        (CwtOidcLabel::FamilyName.to_str(), CwtOidcLabel::FamilyName.into()),
        (CwtOidcLabel::MiddleName.to_str(), CwtOidcLabel::MiddleName.into()),
        (CwtOidcLabel::Name.to_str(), CwtOidcLabel::Nickname.into()),
        (CwtOidcLabel::PreferredUsername.to_str(), CwtOidcLabel::PreferredUsername.into()),
        (CwtOidcLabel::Profile.to_str(), CwtOidcLabel::Profile.into()),
        (CwtOidcLabel::Picture.to_str(), CwtOidcLabel::Picture.into()),
        (CwtOidcLabel::Website.to_str(), CwtOidcLabel::Website.into()),
        (CwtOidcLabel::Email.to_str(), CwtOidcLabel::Email.into()),
        (CwtOidcLabel::EmailVerified.to_str(), CwtOidcLabel::EmailVerified.into()),
        (CwtOidcLabel::Gender.to_str(), CwtOidcLabel::Gender.into()),
        (CwtOidcLabel::Birthdate.to_str(), CwtOidcLabel::Birthdate.into()),
        (CwtOidcLabel::ZoneInfo.to_str(), CwtOidcLabel::ZoneInfo.into()),
        (CwtOidcLabel::Locale.to_str(), CwtOidcLabel::Locale.into()),
        (CwtOidcLabel::PhoneNumber.to_str(), CwtOidcLabel::PhoneNumber.into()),
        (CwtOidcLabel::PhoneNumberVerified.to_str(), CwtOidcLabel::PhoneNumberVerified.into()),
        (CwtOidcLabel::Address.to_str(), CwtOidcLabel::Address.into()),
        (CwtOidcLabel::UpdatedAt.to_str(), CwtOidcLabel::UpdatedAt.into()),
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
            map.serialize_entry(&CwtOidcAddressLabel::Formatted, formatted)?;
        }
        if let Some(street_address) = &self.street_address {
            map.serialize_entry(&CwtOidcAddressLabel::StreetAddress, street_address)?;
        }
        if let Some(locality) = &self.locality {
            map.serialize_entry(&CwtOidcAddressLabel::Locality, locality)?;
        }
        if let Some(region) = &self.region {
            map.serialize_entry(&CwtOidcAddressLabel::Region, region)?;
        }
        if let Some(postal_code) = &self.postal_code {
            map.serialize_entry(&CwtOidcAddressLabel::PostalCode, postal_code)?;
        }
        if let Some(country) = &self.country {
            map.serialize_entry(&CwtOidcAddressLabel::Country, country)?;
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
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::Formatted => {
                            address.formatted.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::StreetAddress => {
                            address.street_address.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::Locality => {
                            address.locality.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::Region => {
                            address.region.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::PostalCode => {
                            address.postal_code.replace(s);
                        }
                        (Value::Integer(i), Value::Text(s)) if i == CwtOidcAddressLabel::Country => {
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
        Ok(self.query(vec![CwtOidcLabel::Name.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::GivenName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::FamilyName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::MiddleName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Nickname.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self
            .query(vec![CwtOidcLabel::PreferredUsername.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Profile.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Picture.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Website.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Email.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self.query(vec![CwtOidcLabel::EmailVerified.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Gender.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Birthdate.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::ZoneInfo.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Locale.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::PhoneNumber.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .query(vec![CwtOidcLabel::PhoneNumberVerified.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self.query(vec![CwtOidcLabel::Address.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CwtOidcLabel::UpdatedAt.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
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

impl<PayloadClaims: Select, Hasher: digest::Digest + Clone, IssuerProtectedClaims: CustomClaims, IssuerUnprotectedClaims: CustomClaims> SpiceOidcSdCwtRead
    for SdCwtVerified<PayloadClaims, Hasher, IssuerProtectedClaims, IssuerUnprotectedClaims>
where
    for<'a> &'a PayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.name()
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.given_name()
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.family_name()
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.middle_name()
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.nickname()
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.preferred_username()
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.0.profile()
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.0.picture()
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        self.0.0.website()
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.email()
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.0.email_verified()
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.gender()
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.birthdate()
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.zoneinfo()
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.locale()
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        self.0.0.phone_number()
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        self.0.0.phone_number_verified()
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        self.0.0.address()
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        self.0.0.updated_at()
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
> SpiceOidcSdCwtRead for KbtCwt<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
where
    for<'a> &'a IssuerPayloadClaims: Into<&'a SpiceOidcClaims>,
{
    fn name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Name.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn given_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::GivenName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn family_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::FamilyName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn middle_name(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::MiddleName.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn nickname(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Nickname.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn preferred_username(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self
            .query(vec![CwtOidcLabel::PreferredUsername.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn profile(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Profile.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn picture(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Picture.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn website(&mut self) -> EsdicawtReadResult<Option<Url>> {
        Ok(self.query(vec![CwtOidcLabel::Website.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Email.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn email_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self.query(vec![CwtOidcLabel::EmailVerified.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn gender(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Gender.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn birthdate(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Birthdate.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn zoneinfo(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::ZoneInfo.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn locale(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::Locale.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number(&mut self) -> EsdicawtReadResult<Option<Cow<str>>> {
        Ok(self.query(vec![CwtOidcLabel::PhoneNumber.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn phone_number_verified(&mut self) -> EsdicawtReadResult<Option<bool>> {
        Ok(self
            .query(vec![CwtOidcLabel::PhoneNumberVerified.into()].into())?
            .as_ref()
            .map(Value::deserialized)
            .transpose()?)
    }

    fn address(&mut self) -> EsdicawtReadResult<Option<OidcAddressClaim>> {
        Ok(self.query(vec![CwtOidcLabel::Address.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
    }

    fn updated_at(&mut self) -> EsdicawtReadResult<Option<i64>> {
        Ok(self.query(vec![CwtOidcLabel::UpdatedAt.into()].into())?.as_ref().map(Value::deserialized).transpose()?)
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
> SpiceOidcSdCwtRead for KbtCwtTagged<IssuerPayloadClaims, Hasher, KbtPayloadClaims, IssuerProtectedClaims, IssuerUnprotectedClaims, KbtProtectedClaims, KbtUnprotectedClaims>
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
        cose_key_set::CoseKeySet, spec::{issuance::SdCwtIssuedTagged, CwtAny}, CborPath, Holder, Issuer,
        Presentation,
        TimeArg,
    };

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn can_issue_and_present_oidc_claim_token() {
        let issuer_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let issuer = Ed25519Issuer::new(issuer_signing_key.clone());
        let cks = CoseKeySet::new(&issuer_signing_key).unwrap();

        let holder_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        let alice_holder = Ed25519Holder::new(holder_signing_key);

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
            matches!(path, [CborPath::Int(i)] if *i == CwtOidcLabel::Name
                     || *i == CwtOidcLabel::GivenName
                     || *i == CwtOidcLabel::FamilyName
                     || *i == CwtOidcLabel::Nickname
                     || *i == CwtOidcLabel::PreferredUsername)
        }));

        let alice_sd_cwt = alice_sd_cwt.to_cbor_bytes().unwrap();
        let alice_sd_cwt = alice_holder.verify_sd_cwt(&alice_sd_cwt, Default::default(), &cks).unwrap();

        let mut alice_kbt = alice_holder
            .new_presentation(
                alice_sd_cwt,
                esdicawt::HolderParams {
                    presentation,
                    audience: "bob",
                    cnonce: None,
                    expiry: Some(TimeArg::Relative(Duration::from_secs(86400))),
                    with_not_before: false,
                    extra_kbt_unprotected: None,
                    extra_kbt_protected: None,
                    extra_kbt_payload: None,
                    artificial_time: None,
                    time_verification: Default::default(),
                    leeway: Default::default(),
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
                    expiry: None,
                    with_not_before: false,
                    leeway: Duration::from_secs(1),
                    key_location: "",
                    holder_confirmation_key: holder_pk.try_into().unwrap(),
                    artificial_time: None,
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
        spec::{reexports::coset, NoClaims, SdHashAlg}, Holder,
        Issuer,
    };
    use esdicawt_spec::EsdicawtSpecError;

    pub struct Ed25519Issuer {
        signing_key: ed25519_dalek::SigningKey,
    }

    impl Issuer for Ed25519Issuer {
        type Error = EsdicawtSpecError;
        type Hasher = sha2::Sha256;
        type Signer = ed25519_dalek::SigningKey;
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
    }

    pub struct Ed25519Holder {
        signing_key: ed25519_dalek::SigningKey,
        verifying_key: ed25519_dalek::VerifyingKey,
    }

    impl Holder for Ed25519Holder {
        type Error = std::convert::Infallible;
        type Signer = ed25519_dalek::SigningKey;

        type Signature = ed25519_dalek::Signature;
        type Verifier = ed25519_dalek::VerifyingKey;

        type Hasher = sha2::Sha256;
        type IssuerProtectedClaims = NoClaims;
        type IssuerUnprotectedClaims = NoClaims;
        type IssuerPayloadClaims = SpiceOidcClaims;
        type KbtUnprotectedClaims = NoClaims;
        type KbtProtectedClaims = NoClaims;

        type KbtPayloadClaims = NoClaims;

        fn new(signing_key: Self::Signer) -> Self {
            Self {
                verifying_key: signing_key.verifying_key(),
                signing_key,
            }
        }

        fn signer(&self) -> &Self::Signer {
            &self.signing_key
        }

        fn cwt_algorithm(&self) -> coset::iana::Algorithm {
            coset::iana::Algorithm::EdDSA
        }

        fn verifier(&self) -> &Self::Verifier {
            &self.verifying_key
        }
    }
}
