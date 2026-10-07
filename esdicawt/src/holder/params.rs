use crate::{
    SdCwtHolderError, SdCwtHolderResult, TimeVerification,
    aead::{AeadSealed, DisclosureEncryptor},
    holder::traverse::{traverse_all_cbor_paths_from_payload, traverse_all_cbor_paths_in_salted_array},
    spec::{
        CustomClaims, NoClaims, SdCwtClaim,
        aead::{AeadEncryptedArray, AeadEncryptedDisclosure, AeadKeyContext, disclosure_to_plaintext},
        blinded_claims::{SaltedArray, SaltedEntry},
    },
    time::TimeArg,
};
use ciborium::Value;

#[derive(Debug)]
pub struct HolderParams<'a, KbtPayloadClaims: CustomClaims = NoClaims, KbtProtectedClaims: CustomClaims = NoClaims, KbtUnprotectedClaims: CustomClaims = NoClaims> {
    pub presentation: Presentation,
    /// Subject, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.3
    pub audience: &'a str,
    /// Client Nonce, see https://www.rfc-editor.org/rfc/rfc9200.html#section-5.3.1
    pub cnonce: Option<&'a [u8]>,
    /// Expiry, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.4
    pub expiry: Option<TimeArg>,
    /// Whether to include a not_before, see https://www.rfc-editor.org/rfc/rfc8392.html#section-3.1.5
    pub with_not_before: bool,
    pub artificial_time: Option<core::time::Duration>,
    pub time_verification: TimeVerification,
    // to accommodate clock skews, applies to exp & nbf
    pub leeway: core::time::Duration,
    pub extra_kbt_protected: Option<KbtProtectedClaims>,
    pub extra_kbt_unprotected: Option<KbtUnprotectedClaims>,
    pub extra_kbt_payload: Option<KbtPayloadClaims>,
    /// To encrypt some of the presented disclosures
    pub encryption: Option<DisclosureEncryption<'a>>,
}

/// Which of the presented disclosures get encrypted and how.
/// They are then moved from `sd_claims` to `sd_aead_encrypted_claims`.
///
/// See https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-encrypted-disclosures
pub struct DisclosureEncryption<'a> {
    pub encryptor: &'a dyn DisclosureEncryptor,
    /// Optional context added to every encrypted disclosure to help the Verifier select the correct key
    pub key_context: Option<AeadKeyContext>,
    /// The presented disclosures whose path, from the root of the payload, is accepted by the function get encrypted,
    /// along with the disclosures nested in them
    #[allow(clippy::type_complexity)]
    pub select: Box<dyn Fn(&[CborPath]) -> bool>,
}

impl DisclosureEncryption<'_> {
    /// Returns the disclosures to keep in plaintext and the encrypted ones
    pub(crate) fn try_encrypt_disclosures<Hasher: digest::Digest, E: core::error::Error + Send + Sync>(
        &self,
        payload: &Value,
        disclosures: SaltedArray,
    ) -> SdCwtHolderResult<(SaltedArray, Option<AeadEncryptedArray>), E> {
        let alg = self.encryptor.algorithm();
        alg.check_allowed()?;

        let selected = {
            let hashed_disclosures = disclosures.digested::<Hasher>()?;
            // paths start at the root of the payload, hence disclosures not reachable from it are never encrypted
            let cbor_paths = traverse_all_cbor_paths_from_payload::<Hasher, E>(payload, &hashed_disclosures)?;
            let encrypted_paths = cbor_paths.iter().filter(|(path, _)| (self.select)(path)).map(|(path, _)| path.clone()).collect::<Vec<_>>();
            // the disclosures nested in an encrypted one are also encrypted. Otherwise, a Verifier unable to decrypt the
            // parent would consider them orphans and reject the whole presentation
            cbor_paths
                .into_iter()
                .filter_map(|(path, salted)| encrypted_paths.iter().any(|encrypted| path.starts_with(encrypted)).then_some(salted))
                .collect::<Vec<_>>()
        };
        // salts being unique, comparing the decoded disclosures is enough. This preserves the raw bytes of the disclosures
        let (to_encrypt, plaintext) = disclosures.partition(|d| d.to_value().map(|d| selected.contains(d)).unwrap_or_default());

        let encrypted = to_encrypt
            .as_slice()
            .iter()
            .map(|disclosure| {
                let plaintext = disclosure_to_plaintext(disclosure)?;
                let AeadSealed { nonce, ciphertext, tag } = self.encryptor.encrypt(&plaintext).map_err(SdCwtHolderError::EncryptionError)?;
                alg.check_tag_len(tag.len())?;
                Ok(AeadEncryptedDisclosure {
                    nonce: nonce.into(),
                    ciphertext: ciphertext.into(),
                    tag: tag.into(),
                    key_context: self.key_context.clone(),
                })
            })
            .collect::<SdCwtHolderResult<Vec<_>, E>>()?;

        let encrypted = if encrypted.is_empty() { None } else { Some(AeadEncryptedArray::try_new(encrypted)?) };
        Ok((plaintext, encrypted))
    }
}

impl std::fmt::Debug for DisclosureEncryption<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisclosureEncryption")
            .field("algorithm", &self.encryptor.algorithm())
            .field("key_context", &self.key_context)
            .finish_non_exhaustive()
    }
}

/// Which disclosures the holder presents to the verifier.
///
/// Decoys are never presented, whatever the variant, since it would reveal to the verifier which digests are decoys.
/// See https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-decoy-digests
#[derive(Default)]
pub enum Presentation {
    /// All the disclosures
    #[default]
    Full,
    /// The disclosures returned by the function
    Custom(Box<dyn Fn(SaltedArray) -> SaltedArray>),
    /// The disclosures whose path is accepted by the function
    #[allow(clippy::type_complexity)]
    Path(Box<dyn Fn(&[CborPath]) -> bool>),
    None,
}

impl std::fmt::Debug for Presentation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::Custom(_) => write!(f, "Custom"),
            Self::Path(_) => write!(f, "Path"),
            Self::None => write!(f, "None"),
        }
    }
}

impl Presentation {
    pub(crate) fn try_select_disclosures<Hasher: digest::Digest, E: core::error::Error + Send + Sync>(&self, disclosures: SaltedArray) -> SdCwtHolderResult<SaltedArray, E> {
        let mut disclosures = match self {
            Self::Full => disclosures,
            Self::None => SaltedArray::default(),
            Self::Custom(f) => f(disclosures),
            Self::Path(f) => {
                let hashed_disclosures = disclosures.digested::<Hasher>()?;
                let cbor_paths = traverse_all_cbor_paths_in_salted_array::<Hasher, E>(&hashed_disclosures)?;
                cbor_paths
                    .into_iter()
                    .filter_map(|(path, salted, ..)| f(&path).then_some(salted.into()))
                    .collect::<Vec<_>>()
                    .into()
            }
        };
        // decoys are never presented since it would reveal to the verifier which digests are decoys
        disclosures.retain(|d| !matches!(d.to_value(), Ok(SaltedEntry::Decoy(_))));
        Ok(disclosures)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum CborPath {
    Str(String),
    Int(i64),
    Any(Value),
    Index(u64),
}

impl From<&SdCwtClaim> for CborPath {
    fn from(name: &SdCwtClaim) -> Self {
        match name {
            SdCwtClaim::Int(i) => Self::Int(*i),
            SdCwtClaim::Tstr(s) => Self::Str(s.clone()),
            SdCwtClaim::TaggedInteger(tag, i) => Self::Any(Value::Tag(*tag, Box::new((*i).into()))),
            SdCwtClaim::TaggedText(tag, s) => Self::Any(Value::Tag(*tag, Box::new(s.as_str().into()))),
            SdCwtClaim::SimpleValue(i) => Self::Any(Value::Simple(*i)),
        }
    }
}

impl TryFrom<&Value> for CborPath {
    type Error = core::num::TryFromIntError;

    fn try_from(name: &Value) -> Result<Self, Self::Error> {
        Ok(match name {
            Value::Integer(i) => Self::Int((*i).try_into()?),
            Value::Text(s) => Self::Str(s.clone()),
            value => Self::Any(value.clone()),
        })
    }
}
