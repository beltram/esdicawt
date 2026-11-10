//! AEAD encrypted disclosures
//!
//! See https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-encrypted-disclosures
use crate::{EsdicawtSpecError, EsdicawtSpecResult, blinded_claims::SaltedEntry, inlined_cbor::InlinedCbor};
use ciborium::Value;
use cose_key::thumbprint::CoseKeyThumbprint;
use serde::ser::SerializeSeq;

/// An AEAD algorithm from the [IANA AEAD Algorithms registry](https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml),
/// carried by the `sd_aead` header parameter.
///
/// The algorithms which MUST NOT be used cannot be represented.
/// See https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html#name-choice-of-aead-algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct AeadAlgorithm(u16);

impl AeadAlgorithm {
    pub const AES_128_GCM: Self = Self(1);
    pub const AES_256_GCM: Self = Self(2);
    pub const CHACHA20_POLY1305: Self = Self(29);

    /// Minimum length of an authentication tag
    pub const MIN_TAG_LEN: usize = 16;

    /// Length of the authentication tag of the AEGIS 'X' variants
    pub const AEGIS_X_TAG_LEN: usize = 32;

    /// The IANA AEAD Algorithm number
    pub const fn id(self) -> u16 {
        self.0
    }

    /// "implementations MUST NOT use any AEAD algorithm with a tag length less than 16 octets" and
    /// "Implementations using the AEGIS algorithms containing an X MUST only use the 256-bit tag variant"
    pub fn check_tag_len(self, len: usize) -> EsdicawtSpecResult<()> {
        // AEAD_AEGIS128X2, AEAD_AEGIS128X4, AEAD_AEGIS256X2, AEAD_AEGIS256X4
        let is_aegis_x = matches!(self.0, 34..=37);
        let valid = if is_aegis_x { len == Self::AEGIS_X_TAG_LEN } else { len >= Self::MIN_TAG_LEN };
        if !valid {
            return Err(EsdicawtSpecError::InvalidAeadTagLength { alg: self.0, len });
        }
        Ok(())
    }
}

impl Default for AeadAlgorithm {
    /// "If present, the algorithm of the `sd_aead` [...] header field is used, or AEAD_AES_128_GCM if no algorithm was specified."
    fn default() -> Self {
        Self::AES_128_GCM
    }
}

impl TryFrom<u16> for AeadAlgorithm {
    type Error = EsdicawtSpecError;

    /// "implementations MUST NOT use algorithms 3 through 14, 18, 19, 21, 22, 24, 25, 27, or 28"
    fn try_from(id: u16) -> Result<Self, Self::Error> {
        if matches!(id, 3..=14 | 18 | 19 | 21 | 22 | 24 | 25 | 27 | 28) {
            return Err(EsdicawtSpecError::ForbiddenAeadAlgorithm(id));
        }
        Ok(Self(id))
    }
}

impl From<AeadAlgorithm> for u16 {
    fn from(alg: AeadAlgorithm) -> Self {
        alg.0
    }
}

/// Optional context to select the correct decryption key
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(untagged)]
pub enum AeadKeyContext {
    Uint(u64),
    Text(String),
    Thumbprint(AeadKeyThumbprint),
}

impl<'de> serde::Deserialize<'de> for AeadKeyContext {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        match Value::deserialize(deserializer)? {
            Value::Integer(i) => u64::try_from(i).map(Self::Uint).map_err(|_| D::Error::custom("An AEAD key context integer must be a uint")),
            Value::Text(s) => Ok(Self::Text(s)),
            Value::Bytes(b) => AeadKeyThumbprint::try_from(b).map(Self::Thumbprint).map_err(D::Error::custom),
            _ => Err(D::Error::custom("An AEAD key context must be a uint, a tstr or a bstr")),
        }
    }
}

/// A COSE Key Thumbprint, see https://www.rfc-editor.org/rfc/rfc9679.html, of any of the digest
/// sizes a [CoseKeyThumbprint] can be computed with
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(untagged)]
pub enum AeadKeyThumbprint {
    /// e.g. SHA-256
    Bytes32(CoseKeyThumbprint<32>),
    /// e.g. SHA-384
    Bytes48(CoseKeyThumbprint<48>),
    /// e.g. SHA-512
    Bytes64(CoseKeyThumbprint<64>),
}

impl PartialEq for AeadKeyThumbprint {
    /// in constant time when both thumbprints have the same size
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        match (self, other) {
            (Self::Bytes32(a), Self::Bytes32(b)) => a.ct_eq(b).into(),
            (Self::Bytes48(a), Self::Bytes48(b)) => a.ct_eq(b).into(),
            (Self::Bytes64(a), Self::Bytes64(b)) => a.ct_eq(b).into(),
            _ => false,
        }
    }
}

impl Eq for AeadKeyThumbprint {}

impl std::hash::Hash for AeadKeyThumbprint {
    /// sizes differ between variants, so hashing the bytes is consistent with [PartialEq]
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (**self).hash(state);
    }
}

impl std::ops::Deref for AeadKeyThumbprint {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Self::Bytes32(t) => t,
            Self::Bytes48(t) => t,
            Self::Bytes64(t) => t,
        }
    }
}

macro_rules! thumbprint_from {
    ($($variant:ident: $n:literal),+) => {$(
        impl From<CoseKeyThumbprint<$n>> for AeadKeyThumbprint {
            fn from(thumbprint: CoseKeyThumbprint<$n>) -> Self {
                Self::$variant(thumbprint)
            }
        }

        impl From<[u8; $n]> for AeadKeyThumbprint {
            fn from(thumbprint: [u8; $n]) -> Self {
                Self::$variant(thumbprint.into())
            }
        }
    )+};
}

thumbprint_from!(Bytes32: 32, Bytes48: 48, Bytes64: 64);

impl TryFrom<Vec<u8>> for AeadKeyThumbprint {
    type Error = EsdicawtSpecError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let len = bytes.len();
        let invalid = |_| EsdicawtSpecError::InvalidAeadKeyThumbprintLength(len);
        Ok(match len {
            32 => <[u8; 32]>::try_from(bytes).map_err(invalid)?.into(),
            48 => <[u8; 48]>::try_from(bytes).map_err(invalid)?.into(),
            64 => <[u8; 64]>::try_from(bytes).map_err(invalid)?.into(),
            _ => return Err(invalid(bytes)),
        })
    }
}

/// `[ nonce, ciphertext, tag, ?aead-key-context ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadEncryptedDisclosure {
    /// nonce of N_MIN octets
    pub nonce: Vec<u8>,
    /// the encryption ciphertext output of a bstr-encoded-salted
    pub ciphertext: Vec<u8>,
    /// the corresponding authentication tag
    pub tag: Vec<u8>,
    /// optional context to select the correct key
    pub key_context: Option<AeadKeyContext>,
}

impl serde::Serialize for AeadEncryptedDisclosure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = if self.key_context.is_some() { 4 } else { 3 };
        let mut array = serializer.serialize_seq(Some(len))?;
        array.serialize_element(serde_bytes::Bytes::new(&self.nonce))?;
        array.serialize_element(serde_bytes::Bytes::new(&self.ciphertext))?;
        array.serialize_element(serde_bytes::Bytes::new(&self.tag))?;
        if let Some(key_context) = &self.key_context {
            array.serialize_element(key_context)?;
        }
        array.end()
    }
}

impl<'de> serde::Deserialize<'de> for AeadEncryptedDisclosure {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let invalid = || D::Error::custom("An AEAD encrypted disclosure must be a [ bstr, bstr, bstr, ?aead-key-context ]");
        let mut items = Value::deserialize(deserializer)?.into_array().map_err(|_| invalid())?.into_iter();
        match (items.next(), items.next(), items.next(), items.next(), items.next()) {
            (Some(Value::Bytes(nonce)), Some(Value::Bytes(ciphertext)), Some(Value::Bytes(tag)), key_context, None) => Ok(Self {
                nonce,
                ciphertext,
                tag,
                key_context: key_context.map(|k| k.deserialized()).transpose().map_err(D::Error::custom)?,
            }),
            _ => Err(invalid()),
        }
    }
}

/// `[ +aead-encrypted ]`. Can never be empty.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AeadEncryptedArray(Vec<AeadEncryptedDisclosure>);

impl AeadEncryptedArray {
    /// [None] when empty
    pub fn new(disclosures: Vec<AeadEncryptedDisclosure>) -> Option<Self> {
        (!disclosures.is_empty()).then_some(Self(disclosures))
    }
}

impl<'de> serde::Deserialize<'de> for AeadEncryptedArray {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        Self::new(Vec::deserialize(deserializer)?).ok_or_else(|| D::Error::custom(EsdicawtSpecError::EmptyAeadEncryptedClaims))
    }
}

impl std::ops::Deref for AeadEncryptedArray {
    type Target = [AeadEncryptedDisclosure];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// The AEAD plaintext of a disclosure: the bstr-encoded disclosure as it would appear in `sd_claims`.
/// These are also the bytes the Redacted Claim Hash is computed over.
pub fn disclosure_to_plaintext(disclosure: &InlinedCbor<SaltedEntry<Value>>) -> EsdicawtSpecResult<Vec<u8>> {
    let raw = disclosure.to_bytes()?;
    Ok(seabored::serde::to_vec(&serde_bytes::Bytes::new(raw))?)
}

/// Reverse of [disclosure_to_plaintext].
///
/// The plaintext must be exactly one byte string in preferred serialization, so that the Redacted Claim Hash is computed
/// over the exact bytes which were authenticated.
pub fn disclosure_from_plaintext(plaintext: &[u8]) -> EsdicawtSpecResult<InlinedCbor<SaltedEntry<Value>>> {
    let raw = ciborium::from_reader::<Value, _>(plaintext)
        .ok()
        .and_then(|v| v.into_bytes().ok())
        .ok_or(EsdicawtSpecError::InvalidDecryptedDisclosure)?;
    let disclosure = InlinedCbor::from_bytes(raw);
    if disclosure_to_plaintext(&disclosure)? != plaintext {
        return Err(EsdicawtSpecError::InvalidDecryptedDisclosure);
    }
    // the decrypted disclosure must be a valid disclosure
    disclosure.to_value().map_err(|_| EsdicawtSpecError::InvalidDecryptedDisclosure)?;
    Ok(disclosure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CwtAny, Salt, SdCwtClaim, blinded_claims::SaltedClaim};

    fn first_disclosure() -> InlinedCbor<SaltedEntry<Value>> {
        // see draft-ietf-spice-sd-cwt/examples/first-disclosure.edn
        let salt: [u8; 16] = hex::decode("bae611067bb823486797da1ebbb52f83").unwrap().try_into().unwrap();
        let entry = SaltedEntry::Claim(SaltedClaim {
            salt: Salt(salt),
            value: Value::from("ABCD-123456"),
            name: SdCwtClaim::Int(501),
        });
        InlinedCbor::from_bytes(entry.to_cbor_bytes().unwrap())
    }

    #[test]
    fn plaintext_should_be_bstr_encoded_disclosure() {
        // see draft-ietf-spice-sd-cwt/examples/first-disclosure.pretty
        let expected = hex::decode("582183".to_owned() + "50bae611067bb823486797da1ebbb52f83" + "6b414243442d313233343536" + "1901f5").unwrap();
        let plaintext = disclosure_to_plaintext(&first_disclosure()).unwrap();
        assert_eq!(plaintext, expected);
        assert_eq!(plaintext.len(), 35);

        let decoded = disclosure_from_plaintext(&plaintext).unwrap();
        assert_eq!(decoded, first_disclosure());
    }

    #[test]
    fn should_reject_invalid_plaintext() {
        let plaintext = disclosure_to_plaintext(&first_disclosure()).unwrap();
        // trailing bytes
        let mut trailing = plaintext.clone();
        trailing.push(0);
        assert!(matches!(disclosure_from_plaintext(&trailing), Err(EsdicawtSpecError::InvalidDecryptedDisclosure)));
        // raw disclosure without its bstr wrapping
        assert!(matches!(
            disclosure_from_plaintext(plaintext.get(2..).unwrap()),
            Err(EsdicawtSpecError::InvalidDecryptedDisclosure)
        ));
        // a text string instead of a byte string
        let mut tstr = plaintext.clone();
        *tstr.first_mut().unwrap() = 0x78;
        assert!(matches!(disclosure_from_plaintext(&tstr), Err(EsdicawtSpecError::InvalidDecryptedDisclosure)));
        // non-preferred length encoding
        let mut non_preferred = vec![0x59, 0x00, 0x21];
        non_preferred.extend_from_slice(plaintext.get(2..).unwrap());
        assert!(matches!(disclosure_from_plaintext(&non_preferred), Err(EsdicawtSpecError::InvalidDecryptedDisclosure)));
        // a bstr which is not a disclosure
        let not_a_disclosure = seabored::serde::to_vec(&serde_bytes::Bytes::new(&[0x01])).unwrap();
        assert!(matches!(disclosure_from_plaintext(&not_a_disclosure), Err(EsdicawtSpecError::InvalidDecryptedDisclosure)));
    }

    #[test]
    fn should_reject_forbidden_algorithms() {
        for alg in [3..=14, 18..=19, 21..=22, 24..=25, 27..=28].into_iter().flatten() {
            assert!(matches!(AeadAlgorithm::try_from(alg), Err(EsdicawtSpecError::ForbiddenAeadAlgorithm(a)) if a == alg));
            // nor decoded
            assert!(AeadAlgorithm::from_cbor_bytes(&alg.to_cbor_bytes().unwrap()).is_err());
        }
        for alg in [1, 2, 15, 16, 17, 20, 23, 26, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39] {
            assert_eq!(AeadAlgorithm::try_from(alg).unwrap().id(), alg);
        }
    }

    #[test]
    fn should_check_tag_length() {
        assert!(AeadAlgorithm::AES_128_GCM.check_tag_len(16).is_ok());
        assert!(AeadAlgorithm::AES_128_GCM.check_tag_len(32).is_ok());
        assert!(matches!(
            AeadAlgorithm::AES_128_GCM.check_tag_len(12),
            Err(EsdicawtSpecError::InvalidAeadTagLength { alg: 1, len: 12 })
        ));
        for aegis_x in 34..=37 {
            assert!(AeadAlgorithm(aegis_x).check_tag_len(32).is_ok());
            assert!(AeadAlgorithm(aegis_x).check_tag_len(16).is_err());
        }
        // non 'X' AEGIS
        assert!(AeadAlgorithm(32).check_tag_len(16).is_ok());
        assert!(AeadAlgorithm(33).check_tag_len(16).is_ok());
    }

    #[test]
    fn default_algorithm_should_be_aes_128_gcm() {
        assert_eq!(AeadAlgorithm::default(), AeadAlgorithm(1));
    }

    #[test]
    fn algorithm_should_be_uint_of_size_2() {
        assert_eq!(AeadAlgorithm(29).to_cbor_bytes().unwrap(), vec![0x18, 29]);
        assert_eq!(AeadAlgorithm::from_cbor_bytes(&[0x18, 29]).unwrap(), AeadAlgorithm(29));
        assert_eq!(AeadAlgorithm::from_cbor_bytes(&[0x19, 0xff, 0xff]).unwrap(), AeadAlgorithm(u16::MAX));
        // 65536
        assert!(AeadAlgorithm::from_cbor_bytes(&[0x1a, 0x00, 0x01, 0x00, 0x00]).is_err());
        // -1
        assert!(AeadAlgorithm::from_cbor_bytes(&[0x20]).is_err());
    }

    fn encrypted(key_context: Option<AeadKeyContext>) -> AeadEncryptedDisclosure {
        AeadEncryptedDisclosure {
            nonce: vec![1; 12],
            ciphertext: vec![2; 35],
            tag: vec![3; 16],
            key_context,
        }
    }

    #[test]
    fn encrypted_disclosure_should_roundtrip() {
        let key_contexts = [
            None,
            Some(AeadKeyContext::Uint(42)),
            Some(AeadKeyContext::Text("kid".into())),
            Some(AeadKeyContext::Thumbprint([4; 32].into())),
            Some(AeadKeyContext::Thumbprint([5; 48].into())),
            Some(AeadKeyContext::Thumbprint([6; 64].into())),
        ];
        for key_context in key_contexts {
            let expected_len = if key_context.is_some() { 4 } else { 3 };
            let encrypted = encrypted(key_context);
            let bytes = encrypted.to_cbor_bytes().unwrap();
            assert_eq!(Value::from_cbor_bytes(&bytes).unwrap().into_array().unwrap().len(), expected_len);
            assert_eq!(AeadEncryptedDisclosure::from_cbor_bytes(&bytes).unwrap(), encrypted);
            // also from a Value, as done when decoding the unprotected header
            assert_eq!(Value::from_cbor_bytes(&bytes).unwrap().deserialized::<AeadEncryptedDisclosure>().unwrap(), encrypted);
        }
    }

    #[test]
    fn should_decode_draft_example() {
        // see draft-ietf-spice-sd-cwt/examples/aead-claim-array.edn
        let nonce = hex::decode("95d0040fe650e5baf51c907c").unwrap();
        let ciphertext = hex::decode("563a7d9f0f65d40b751fbc3fcc408e8fe27c375b60a4727b1f1e9572c07992eb5ec5a9").unwrap();
        let tag = hex::decode("9f4d37da32187528416ed7ee95e0625f").unwrap();
        let value = Value::Array(vec![Value::Bytes(nonce.clone()), Value::Bytes(ciphertext.clone()), Value::Bytes(tag.clone())]);
        let expected = AeadEncryptedDisclosure {
            nonce,
            ciphertext,
            tag,
            key_context: None,
        };
        assert_eq!(value.deserialized::<AeadEncryptedDisclosure>().unwrap(), expected);
    }

    #[test]
    fn should_reject_malformed_encrypted_disclosure() {
        let b = |n: usize| Value::Bytes(vec![0; n]);
        let invalid = [
            // too few
            Value::Array(vec![b(12), b(35)]),
            // too many
            Value::Array(vec![b(12), b(35), b(16), Value::from(1), Value::from(2)]),
            // nonce not a bstr
            Value::Array(vec![Value::from("nonce"), b(35), b(16)]),
            // tag not a bstr
            Value::Array(vec![b(12), b(35), Value::from(1)]),
            // negative key context
            Value::Array(vec![b(12), b(35), b(16), Value::from(-1)]),
            // invalid key context type
            Value::Array(vec![b(12), b(35), b(16), Value::Array(vec![])]),
            Value::Array(vec![b(12), b(35), b(16), Value::Bool(true)]),
            // thumbprint of an unsupported size
            Value::Array(vec![b(12), b(35), b(16), b(0)]),
            Value::Array(vec![b(12), b(35), b(16), b(20)]),
            Value::Array(vec![b(12), b(35), b(16), b(33)]),
            // not an array
            b(12),
        ];
        for value in invalid {
            assert!(value.deserialized::<AeadEncryptedDisclosure>().is_err(), "{value:?} should be invalid");
        }
    }

    #[test]
    fn encrypted_array_should_not_be_empty() {
        assert!(AeadEncryptedArray::new(vec![]).is_none());
        assert!(Value::Array(vec![]).deserialized::<AeadEncryptedArray>().is_err());
        assert!(AeadEncryptedArray::from_cbor_bytes(&[0x80]).is_err());

        let array = AeadEncryptedArray::new(vec![encrypted(None)]).unwrap();
        let bytes = array.to_cbor_bytes().unwrap();
        assert_eq!(AeadEncryptedArray::from_cbor_bytes(&bytes).unwrap(), array);
    }
}
