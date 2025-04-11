//! TODO: if teh RFC defines a finite subset of hash_alg, turn these into enums with stack allocated arrays of the exact size 💡

use crate::{CwtAny, EsdicawtSpecResult, REDACTED_CLAIM_ELEMENT_TAG};
use ciborium::Value;

/// Digest of a claim in a CBOR Mapping represented by a [crate::blinded_claims::SaltedClaim] in the disclosures
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct RedactedClaimKey(serde_bytes::ByteBuf);

impl From<Vec<u8>> for RedactedClaimKey {
    fn from(v: Vec<u8>) -> Self {
        Self(v.into())
    }
}

impl From<&[u8]> for RedactedClaimKey {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec().into())
    }
}

impl std::ops::Deref for RedactedClaimKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct RedactedClaimKeyRef<'a>(#[serde(borrow)] &'a serde_bytes::Bytes);

impl std::ops::Deref for RedactedClaimKeyRef<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RedactedClaimKeys(Vec<RedactedClaimKey>);

impl RedactedClaimKeys {
    pub const CWT_LABEL: u8 = crate::CWT_LABEL_REDACTED_KEYS;

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn push(&mut self, redacted_claim_key: impl Into<RedactedClaimKey>) {
        self.0.push(redacted_claim_key.into())
    }

    pub fn into_map_entry(self) -> EsdicawtSpecResult<(Value, Value)> {
        let k = Value::Simple(Self::CWT_LABEL);
        let v = self.to_cbor_value()?;
        Ok((k, v))
    }
}

impl std::ops::Deref for RedactedClaimKeys {
    type Target = [RedactedClaimKey];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RedactedClaimKeysRef<'a>(#[serde(borrow)] Vec<RedactedClaimKeyRef<'a>>);

impl<'a> std::ops::Deref for RedactedClaimKeysRef<'a> {
    type Target = [RedactedClaimKeyRef<'a>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Digest of a value in a CBOR Array represented by a [crate::blinded_claims::SaltedElement] in the disclosures
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RedactedClaimElement(ciborium::tag::Required<serde_bytes::ByteBuf, REDACTED_CLAIM_ELEMENT_TAG>);

impl From<&[u8]> for RedactedClaimElement {
    fn from(v: &[u8]) -> Self {
        Self(ciborium::tag::Required(v.to_vec().into()))
    }
}

impl std::ops::Deref for RedactedClaimElement {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}
