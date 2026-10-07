//! AEAD encrypted disclosures
//!
//! See https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-encrypted-disclosures
use crate::{EsdicawtSpecError, EsdicawtSpecResult, blinded_claims::SaltedEntry, inlined_cbor::InlinedCbor};
use ciborium::Value;
use serde::ser::SerializeSeq;

/// An AEAD algorithm from the [IANA AEAD Algorithms registry](https://www.iana.org/assignments/aead-parameters/aead-parameters.xhtml),
/// carried by the `sd_aead` header parameter
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct AeadAlgorithm(pub u16);

impl AeadAlgorithm {
    pub const AES_128_GCM: Self = Self(1);
    pub const AES_256_GCM: Self = Self(2);
    pub const CHACHA20_POLY1305: Self = Self(29);

    /// Minimum length of an authentication tag
    pub const MIN_TAG_LEN: usize = 16;

    /// Length of the authentication tag of the AEGIS 'X' variants
    pub const AEGIS_X_TAG_LEN: usize = 32;

    /// Algorithms which MUST NOT be used.
    /// See https://datatracker.ietf.org/doc/html/draft-ietf-spice-sd-cwt#name-choice-of-aead-algorithms
    pub fn is_forbidden(&self) -> bool {
        matches!(self.0, 3..=14 | 18 | 19 | 21 | 22 | 24 | 25 | 27 | 28)
    }

    /// AEAD_AEGIS128X2, AEAD_AEGIS128X4, AEAD_AEGIS256X2, AEAD_AEGIS256X4
    pub fn is_aegis_x(&self) -> bool {
        matches!(self.0, 34..=37)
    }

    /// Verifies this algorithm can be used for encrypted disclosures
    pub fn check_allowed(&self) -> EsdicawtSpecResult<()> {
        if self.is_forbidden() {
            return Err(EsdicawtSpecError::ForbiddenAeadAlgorithm(self.0));
        }
        Ok(())
    }

    /// "implementations MUST NOT use any AEAD algorithm with a tag length less than 16 octets" and
    /// "Implementations using the AEGIS algorithms containing an X MUST only use the 256-bit tag variant"
    pub fn check_tag_len(&self, len: usize) -> EsdicawtSpecResult<()> {
        let valid = if self.is_aegis_x() { len == Self::AEGIS_X_TAG_LEN } else { len >= Self::MIN_TAG_LEN };
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

impl From<u16> for AeadAlgorithm {
    fn from(v: u16) -> Self {
        Self(v)
    }
}

/// Optional context to select the correct decryption key
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AeadKeyContext {
    Uint(u64),
    Text(String),
    /// A COSE Key Thumbprint, see https://www.rfc-editor.org/rfc/rfc9679.html
    Thumbprint(serde_bytes::ByteBuf),
}

impl serde::Serialize for AeadKeyContext {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Uint(i) => serializer.serialize_u64(*i),
            Self::Text(s) => serializer.serialize_str(s),
            Self::Thumbprint(b) => serializer.serialize_bytes(b),
        }
    }
}

impl<'de> serde::Deserialize<'de> for AeadKeyContext {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AeadKeyContextVisitor;

        impl serde::de::Visitor<'_> for AeadKeyContextVisitor {
            type Value = AeadKeyContext;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an AEAD key context (uint / tstr / bstr)")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                Ok(AeadKeyContext::Uint(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Self::Value, E> {
                let v = u64::try_from(v).map_err(|_| E::custom("An AEAD key context cannot be a negative integer"))?;
                Ok(AeadKeyContext::Uint(v))
            }

            fn visit_u128<E: serde::de::Error>(self, v: u128) -> Result<Self::Value, E> {
                let v = u64::try_from(v).map_err(|_| E::custom("An AEAD key context integer must fit in a uint"))?;
                Ok(AeadKeyContext::Uint(v))
            }

            fn visit_i128<E: serde::de::Error>(self, v: i128) -> Result<Self::Value, E> {
                let v = u64::try_from(v).map_err(|_| E::custom("An AEAD key context integer must fit in a uint"))?;
                Ok(AeadKeyContext::Uint(v))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                Ok(AeadKeyContext::Text(v.to_string()))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                Ok(AeadKeyContext::Text(v))
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(AeadKeyContext::Thumbprint(v.to_vec().into()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(AeadKeyContext::Thumbprint(v.into()))
            }
        }

        deserializer.deserialize_any(AeadKeyContextVisitor)
    }
}

/// `[ nonce, ciphertext, tag, ?aead-key-context ]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AeadEncryptedDisclosure {
    /// nonce of N_MIN octets
    pub nonce: serde_bytes::ByteBuf,
    /// the encryption ciphertext output of a bstr-encoded-salted
    pub ciphertext: serde_bytes::ByteBuf,
    /// the corresponding authentication tag
    pub tag: serde_bytes::ByteBuf,
    /// optional context to select the correct key
    pub key_context: Option<AeadKeyContext>,
}

impl serde::Serialize for AeadEncryptedDisclosure {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let len = if self.key_context.is_some() { 4 } else { 3 };
        let mut array = serializer.serialize_seq(Some(len))?;
        array.serialize_element(&self.nonce)?;
        array.serialize_element(&self.ciphertext)?;
        array.serialize_element(&self.tag)?;
        if let Some(key_context) = &self.key_context {
            array.serialize_element(key_context)?;
        }
        array.end()
    }
}

impl<'de> serde::Deserialize<'de> for AeadEncryptedDisclosure {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct AeadEncryptedVisitor;

        impl<'de> serde::de::Visitor<'de> for AeadEncryptedVisitor {
            type Value = AeadEncryptedDisclosure;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "an AEAD encrypted disclosure")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;

                let nonce = seq.next_element::<Bstr>()?.ok_or_else(|| A::Error::custom("Missing nonce in AEAD encrypted disclosure"))?;
                let ciphertext = seq
                    .next_element::<Bstr>()?
                    .ok_or_else(|| A::Error::custom("Missing ciphertext in AEAD encrypted disclosure"))?;
                let tag = seq.next_element::<Bstr>()?.ok_or_else(|| A::Error::custom("Missing tag in AEAD encrypted disclosure"))?;
                let key_context = seq.next_element::<AeadKeyContext>()?;
                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(A::Error::custom("Too many elements in AEAD encrypted disclosure"));
                }

                Ok(AeadEncryptedDisclosure {
                    nonce: nonce.0,
                    ciphertext: ciphertext.0,
                    tag: tag.0,
                    key_context,
                })
            }
        }

        deserializer.deserialize_seq(AeadEncryptedVisitor)
    }
}

/// A CBOR byte string, strictly. Unlike [serde_bytes::ByteBuf] it does not accept a text string
struct Bstr(serde_bytes::ByteBuf);

impl<'de> serde::Deserialize<'de> for Bstr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BstrVisitor;

        impl serde::de::Visitor<'_> for BstrVisitor {
            type Value = Bstr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte string")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(Bstr(v.to_vec().into()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                Ok(Bstr(v.into()))
            }
        }

        deserializer.deserialize_bytes(BstrVisitor)
    }
}

/// `[ +aead-encrypted ]`. Can never be empty.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AeadEncryptedArray(Vec<AeadEncryptedDisclosure>);

impl AeadEncryptedArray {
    pub fn try_new(disclosures: Vec<AeadEncryptedDisclosure>) -> EsdicawtSpecResult<Self> {
        if disclosures.is_empty() {
            return Err(EsdicawtSpecError::EmptyAeadEncryptedClaims);
        }
        Ok(Self(disclosures))
    }

    pub fn into_inner(self) -> Vec<AeadEncryptedDisclosure> {
        self.0
    }
}

impl<'de> serde::Deserialize<'de> for AeadEncryptedArray {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let disclosures = Vec::<AeadEncryptedDisclosure>::deserialize(deserializer)?;
        Self::try_new(disclosures).map_err(D::Error::custom)
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
            assert!(matches!(AeadAlgorithm(alg).check_allowed(), Err(EsdicawtSpecError::ForbiddenAeadAlgorithm(a)) if a == alg));
        }
        for alg in [1, 2, 15, 16, 17, 20, 23, 26, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39] {
            assert!(AeadAlgorithm(alg).check_allowed().is_ok());
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
            nonce: vec![1; 12].into(),
            ciphertext: vec![2; 35].into(),
            tag: vec![3; 16].into(),
            key_context,
        }
    }

    #[test]
    fn encrypted_disclosure_should_roundtrip() {
        let key_contexts = [
            None,
            Some(AeadKeyContext::Uint(42)),
            Some(AeadKeyContext::Text("kid".into())),
            Some(AeadKeyContext::Thumbprint(vec![4; 32].into())),
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
        let decoded = value.deserialized::<AeadEncryptedDisclosure>().unwrap();
        assert_eq!(decoded.nonce.as_slice(), nonce);
        assert_eq!(decoded.ciphertext.as_slice(), ciphertext);
        assert_eq!(decoded.tag.as_slice(), tag);
        assert_eq!(decoded.key_context, None);
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
            // not an array
            b(12),
        ];
        for value in invalid {
            assert!(value.deserialized::<AeadEncryptedDisclosure>().is_err(), "{value:?} should be invalid");
        }
    }

    #[test]
    fn encrypted_array_should_not_be_empty() {
        assert!(matches!(AeadEncryptedArray::try_new(vec![]), Err(EsdicawtSpecError::EmptyAeadEncryptedClaims)));
        assert!(Value::Array(vec![]).deserialized::<AeadEncryptedArray>().is_err());
        assert!(AeadEncryptedArray::from_cbor_bytes(&[0x80]).is_err());

        let array = AeadEncryptedArray::try_new(vec![encrypted(None)]).unwrap();
        let bytes = array.to_cbor_bytes().unwrap();
        assert_eq!(AeadEncryptedArray::from_cbor_bytes(&bytes).unwrap(), array);
    }
}
