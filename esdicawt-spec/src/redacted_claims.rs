use crate::{CwtAny, EsdicawtSpecResult, REDACTED_CLAIM_ELEMENT_TAG, blinded_claims::LazyRedacted};
use ciborium::Value;
use std::rc::Rc;

/// Digest of a claim in a CBOR Mapping represented by a [crate::blinded_claims::SaltedClaim] in the disclosures
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct RedactedClaimHash(serde_bytes::ByteBuf);

impl From<Vec<u8>> for RedactedClaimHash {
    fn from(v: Vec<u8>) -> Self {
        Self(v.into())
    }
}

impl From<&[u8]> for RedactedClaimHash {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec().into())
    }
}

impl std::ops::Deref for RedactedClaimHash {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub trait ToRedacted: serde::Serialize {
    fn to_redacted_bstr(&self) -> EsdicawtSpecResult<Vec<u8>> {
        let mut cbor_bytes = vec![];
        ciborium::into_writer(self, &mut cbor_bytes)?;
        Value::Bytes(cbor_bytes).to_cbor_bytes()
    }

    #[cfg(feature = "backward")]
    fn old_to_redacted_bstr(&self) -> EsdicawtSpecResult<Vec<u8>> {
        let mut cbor_bytes = vec![];
        ciborium::into_writer(self, &mut cbor_bytes)?;
        Ok(cbor_bytes)
    }

    fn to_redacted<H: digest::Digest>(&self) -> EsdicawtSpecResult<digest::Output<H>> {
        Ok(H::digest(self.to_redacted_bstr()?))
    }

    #[cfg(feature = "backward")]
    fn old_to_redacted<H: digest::Digest>(&self) -> EsdicawtSpecResult<digest::Output<H>> {
        Ok(H::digest(self.old_to_redacted_bstr()?))
    }

    fn to_redacted_detached_hasher(&self, hasher: Rc<dyn digest::DynDigest>) -> EsdicawtSpecResult<Vec<u8>> {
        let mut h = hasher.box_clone();
        h.update(&self.to_redacted_bstr()?);
        Ok(h.finalize().to_vec())
    }

    #[cfg(feature = "backward")]
    fn old_to_redacted_detached_hasher(&self, hasher: Rc<dyn digest::DynDigest>) -> EsdicawtSpecResult<Vec<u8>> {
        let mut h = hasher.box_clone();
        h.update(&self.old_to_redacted_bstr()?);
        Ok(h.finalize().to_vec())
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
pub struct RedactedClaimKeys(pub Vec<RedactedClaimHash>);

impl RedactedClaimKeys {
    pub const CWT_LABEL: u8 = crate::CWT_LABEL_REDACTED_TAG;

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn push<H: digest::Digest>(&mut self, salted_claim: &impl ToRedacted) -> EsdicawtSpecResult<()> {
        self.0.push(salted_claim.to_redacted::<H>()?.as_ref().into());
        Ok(())
    }

    pub fn into_map_entry(self) -> EsdicawtSpecResult<(Value, Value)> {
        let k = Value::Simple(Self::CWT_LABEL);
        let v = self.to_cbor_value()?;
        Ok((k, v))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn contains_redacted(&self, x: &LazyRedacted) -> bool {
        self.0.iter().any(|h| h == x)
    }
}

impl IntoIterator for RedactedClaimKeys {
    type Item = RedactedClaimHash;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
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
pub struct RedactedClaimElement(ciborium::tag::RequireExact<serde_bytes::ByteBuf, REDACTED_CLAIM_ELEMENT_TAG>);

impl RedactedClaimElement {
    pub fn from_salted_entry<H: digest::Digest>(salted_entry: &impl ToRedacted) -> EsdicawtSpecResult<Self> {
        Ok(salted_entry.to_redacted::<H>()?.as_ref().into())
    }
}

impl From<&[u8]> for RedactedClaimElement {
    #[inline(always)]
    fn from(v: &[u8]) -> Self {
        v.to_vec().into()
    }
}

impl From<Vec<u8>> for RedactedClaimElement {
    fn from(v: Vec<u8>) -> Self {
        Self(ciborium::tag::RequireExact(v.into()))
    }
}

impl std::ops::Deref for RedactedClaimElement {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0.0
    }
}
