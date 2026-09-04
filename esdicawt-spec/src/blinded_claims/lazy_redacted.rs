use crate::redacted_claims::{RedactedClaimElement, RedactedClaimHash, ToRedacted};
use std::{rc::Rc, sync::OnceLock};

#[cfg(not(feature = "backward"))]
#[derive(Default, Debug, Clone)]
pub struct LazyRedacted(OnceLock<Vec<u8>>);

#[cfg(feature = "backward")]
#[derive(Default, Debug, Clone)]
pub struct LazyRedacted(OnceLock<(Vec<u8>, Vec<u8>)>);

#[cfg(not(feature = "backward"))]
impl LazyRedacted {
    pub fn or_init<H: digest::Digest>(&self, to_redact: &impl ToRedacted) {
        self.0.get_or_init(|| to_redact.to_redacted::<H>().map(|r| r.to_vec()).unwrap_or_default());
    }

    pub fn or_init_detached_hasher(&self, to_redact: &impl ToRedacted, hasher: &Rc<dyn digest::DynDigest>) {
        self.0.get_or_init(|| to_redact.to_redacted_detached_hasher(hasher.clone()).unwrap_or_default());
    }
}

#[cfg(feature = "backward")]
impl LazyRedacted {
    pub fn or_init<H: digest::Digest>(&self, to_redact: &impl ToRedacted) {
        self.0.get_or_init(|| {
            let new = to_redact.to_redacted::<H>().map(|r| r.to_vec()).unwrap_or_default();
            let old = to_redact.old_to_redacted::<H>().map(|r| r.to_vec()).unwrap_or_default();
            (new, old)
        });
    }

    pub fn or_init_detached_hasher(&self, to_redact: &impl ToRedacted, hasher: &Rc<dyn digest::DynDigest>) {
        self.0.get_or_init(|| {
            let new = to_redact.to_redacted_detached_hasher(hasher.clone()).map(|r| r.to_vec()).unwrap_or_default();
            let old = to_redact.old_to_redacted_detached_hasher(hasher.clone()).map(|r| r.to_vec()).unwrap_or_default();
            (new, old)
        });
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<RedactedClaimHash> for LazyRedacted {
    fn eq(&self, other: &RedactedClaimHash) -> bool {
        self.get().map(|v| **v == **other).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<LazyRedacted> for RedactedClaimHash {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|v| **v == **self).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<RedactedClaimElement> for LazyRedacted {
    fn eq(&self, other: &RedactedClaimElement) -> bool {
        self.get().map(|v| **v == **other).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<LazyRedacted> for RedactedClaimElement {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|v| **v == **self).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<&[u8]> for LazyRedacted {
    fn eq(&self, other: &&[u8]) -> bool {
        self.get().map(|v| **v == **other).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl PartialEq<LazyRedacted> for &[u8] {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|v| **v == **self).unwrap_or_default()
    }
}

#[cfg(not(feature = "backward"))]
impl std::ops::Deref for LazyRedacted {
    type Target = OnceLock<Vec<u8>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(feature = "backward")]
impl PartialEq<RedactedClaimHash> for LazyRedacted {
    fn eq(&self, other: &RedactedClaimHash) -> bool {
        self.get().map(|(new, old)| **new == **other || **old == **other).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl PartialEq<LazyRedacted> for RedactedClaimHash {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|(new, old)| **new == **self || **old == **self).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl PartialEq<RedactedClaimElement> for LazyRedacted {
    fn eq(&self, other: &RedactedClaimElement) -> bool {
        self.get().map(|(new, old)| **new == **other || **old == **other).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl PartialEq<LazyRedacted> for RedactedClaimElement {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|(new, old)| **new == **self || **old == **self).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl PartialEq<&[u8]> for LazyRedacted {
    fn eq(&self, other: &&[u8]) -> bool {
        self.get().map(|(new, old)| **new == **other || **old == **other).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl PartialEq<LazyRedacted> for &[u8] {
    fn eq(&self, other: &LazyRedacted) -> bool {
        other.get().map(|(new, old)| **new == **self || **old == **self).unwrap_or_default()
    }
}

#[cfg(feature = "backward")]
impl std::ops::Deref for LazyRedacted {
    type Target = OnceLock<(Vec<u8>, Vec<u8>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
