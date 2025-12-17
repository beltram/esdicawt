use coset::iana;

pub mod error;

/// Proof of possession key according to [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747)
///
/// To use in the "cnf" claim
/// see https://www.iana.org/assignments/cwt/cwt.xhtml#confirmation-methods for IANA consideration
#[derive(Debug, Clone, PartialEq)]
#[repr(i64)]
pub enum KeyConfirmation {
    CoseKey(cose_key::CoseKey) = Self::COSE_KEY_CLAIM,
    EncryptedCoseKey(Box<EncryptedCoseKey>) = Self::ENCRYPTED_COSE_KEY_CLAIM,
    Kid(serde_bytes::ByteBuf) = Self::KID_CLAIM,
    // see https://datatracker.ietf.org/doc/html/rfc9679#name-confirmation-method
    #[cfg(feature = "thumbprint")]
    Thumbprint(cose_key_thumbprint::CoseKeyThumbprint<32>) = Self::THUMBPRINT_CLAIM,
}

#[derive(Debug, PartialEq, Clone)]
pub enum EncryptedCoseKey {
    Global(coset::CoseEncrypt0),
    ToRecipients(coset::CoseEncrypt),
}

impl KeyConfirmation {
    // see https://www.rfc-editor.org/rfc/rfc8747.html#section-3.2
    const COSE_KEY_CLAIM: i64 = 1;
    // see https://www.rfc-editor.org/rfc/rfc8747.html#section-3.3
    const ENCRYPTED_COSE_KEY_CLAIM: i64 = 2;
    // see https://www.rfc-editor.org/rfc/rfc8747.html#section-3.4
    const KID_CLAIM: i64 = 3;
    // see https://datatracker.ietf.org/doc/html/rfc9679#name-iana-considerations
    #[cfg(feature = "thumbprint")]
    const THUMBPRINT_CLAIM: i64 = 5;
}

impl serde::Serialize for KeyConfirmation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error as _, SerializeMap as _};

        let mut map = serializer.serialize_map(Some(1))?;
        // see https://www.iana.org/assignments/cwt/cwt.xhtml#confirmation-methods
        use coset::AsCborValue as _;
        match self {
            Self::CoseKey(cose_key) => map.serialize_entry(&Self::COSE_KEY_CLAIM, cose_key)?,
            Self::EncryptedCoseKey(enc_cose_key) => {
                let value = match enc_cose_key.as_ref() {
                    EncryptedCoseKey::Global(cose) => cose.clone().to_cbor_value().map_err(S::Error::custom)?,
                    EncryptedCoseKey::ToRecipients(cose) => cose.clone().to_cbor_value().map_err(S::Error::custom)?,
                };
                map.serialize_entry(&Self::ENCRYPTED_COSE_KEY_CLAIM, &value)?
            }
            Self::Kid(value) => map.serialize_entry(&Self::KID_CLAIM, value)?,
            #[cfg(feature = "thumbprint")]
            Self::Thumbprint(thumbprint) => map.serialize_entry(&Self::THUMBPRINT_CLAIM, &thumbprint)?,
        };
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for KeyConfirmation {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct KeyConfirmationVisitor;

        impl<'de> serde::de::Visitor<'de> for KeyConfirmationVisitor {
            type Value = KeyConfirmation;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a KeyConfirmation struct")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                use serde::de::Error as _;
                let Some(key) = map.next_key::<i64>()? else {
                    return Err(A::Error::custom("No KeyConfirmation identifier"));
                };

                use coset::AsCborValue as _;
                Ok(match key {
                    Self::Value::COSE_KEY_CLAIM => Self::Value::CoseKey(map.next_value::<cose_key::CoseKey>().map_err(A::Error::custom)?),
                    Self::Value::ENCRYPTED_COSE_KEY_CLAIM => {
                        // TODO: optimize & prevent this clone
                        let value = map.next_value::<ciborium::Value>().map_err(A::Error::custom)?;
                        Self::Value::EncryptedCoseKey(if let Ok(to_recipient) = coset::CoseEncrypt::from_cbor_value(value.clone()) {
                            Box::new(EncryptedCoseKey::ToRecipients(to_recipient))
                        } else if let Ok(global) = coset::CoseEncrypt0::from_cbor_value(value) {
                            Box::new(EncryptedCoseKey::Global(global))
                        } else {
                            return Err(A::Error::custom("Invalid Encrypted_COSE_Key"));
                        })
                    }
                    Self::Value::KID_CLAIM => Self::Value::Kid(map.next_value::<serde_bytes::ByteBuf>().map_err(A::Error::custom)?),
                    #[cfg(feature = "thumbprint")]
                    Self::Value::THUMBPRINT_CLAIM => KeyConfirmation::Thumbprint(map.next_value::<cose_key_thumbprint::CoseKeyThumbprint>().map_err(A::Error::custom)?),
                    unknown => {
                        return Err(A::Error::custom(format!("Unknown KeyConfirmation discriminant: {unknown}",)));
                    }
                })
            }
        }

        deserializer.deserialize_map(KeyConfirmationVisitor)
    }
}

impl KeyConfirmation {
    pub fn alg(&self) -> Option<iana::Algorithm> {
        match self {
            Self::CoseKey(key) => key.alg(),
            _ => None,
        }
    }

    pub fn crv(&self) -> Option<iana::EllipticCurve> {
        match self {
            Self::CoseKey(key) => key.crv(),
            _ => None,
        }
    }
}

#[cfg(feature = "pem")]
mod pem {
    use super::*;
    use cose_key::{CoseKey, CoseKeyError};

    impl pkcs8::EncodePublicKey for KeyConfirmation {
        fn to_public_key_der(&self) -> pkcs8::spki::Result<pkcs8::Document> {
            match self {
                Self::CoseKey(cose_key) => cose_key.to_public_key_der(),
                _ => Err(pkcs8::spki::Error::AlgorithmParametersMissing),
            }
        }
    }

    impl KeyConfirmation {
        pub fn from_public_key_pem<K: pkcs8::DecodePublicKey + TryInto<CoseKey, Error = E>, E: Into<CoseKeyError>>(s: &str) -> Result<Self, error::CoseKeyConfirmationError> {
            Ok(Self::CoseKey(CoseKey::from_public_key_pem::<K, E>(s)?))
        }
    }
}

#[cfg(feature = "thumbprint")]
impl KeyConfirmation {
    pub fn new_thumbprint(pk: impl TryInto<cose_key::CoseKey, Error: Into<error::CoseKeyConfirmationError>>) -> Result<Self, error::CoseKeyConfirmationError> {
        let key = pk.try_into().map_err(Into::into)?;
        let thumbprint = cose_key_thumbprint::CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(key)?;
        Ok(Self::Thumbprint(thumbprint))
    }
}

#[cfg(feature = "ed25519")]
mod ed25519 {
    use super::*;

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
    impl TryFrom<&ed25519_dalek::VerifyingKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(pk: &ed25519_dalek::VerifyingKey) -> Result<Self, Self::Error> {
            Ok(Self::CoseKey(cose_key::CoseKey::from(pk)))
        }
    }

    impl TryFrom<&ed25519_dalek::SigningKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(sk: &ed25519_dalek::SigningKey) -> Result<Self, Self::Error> {
            (&sk.verifying_key()).try_into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&KeyConfirmation> for ed25519_dalek::VerifyingKey {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
            match cnf {
                KeyConfirmation::CoseKey(key) => Ok(key.try_into()?),
                _ => Err(error::CoseKeyConfirmationError::NotCoseKey),
            }
        }
    }
}

#[cfg(feature = "p256")]
mod ec_p256 {
    use super::*;

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
    impl TryFrom<&p256::PublicKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(pk: &p256::PublicKey) -> Result<Self, Self::Error> {
            Ok(Self::CoseKey(cose_key::CoseKey::try_from(pk)?))
        }
    }

    impl TryFrom<&p256::ecdsa::VerifyingKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(vk: &p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            Self::try_from(&p256::PublicKey::from(vk))
        }
    }

    impl TryFrom<&p256::ecdsa::SigningKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(sk: &p256::ecdsa::SigningKey) -> Result<Self, Self::Error> {
            sk.as_ref().try_into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&KeyConfirmation> for p256::PublicKey {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
            match cnf {
                KeyConfirmation::CoseKey(key) => Ok(key.try_into()?),
                _ => Err(error::CoseKeyConfirmationError::NotCoseKey),
            }
        }
    }

    impl TryFrom<&KeyConfirmation> for p256::ecdsa::VerifyingKey {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
            Ok(Self::from(p256::PublicKey::try_from(cnf)?))
        }
    }
}

#[cfg(feature = "p384")]
mod ec_p384 {
    use super::*;

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
    impl TryFrom<&p384::PublicKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(pk: &p384::PublicKey) -> Result<Self, Self::Error> {
            Ok(Self::CoseKey(cose_key::CoseKey::try_from(pk)?))
        }
    }

    impl TryFrom<&p384::ecdsa::VerifyingKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(vk: &p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            Self::try_from(&p384::PublicKey::from(vk))
        }
    }

    impl TryFrom<&p384::ecdsa::SigningKey> for KeyConfirmation {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(sk: &p384::ecdsa::SigningKey) -> Result<Self, Self::Error> {
            sk.as_ref().try_into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&KeyConfirmation> for p384::PublicKey {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
            match cnf {
                KeyConfirmation::CoseKey(key) => Ok(key.try_into()?),
                _ => Err(error::CoseKeyConfirmationError::NotCoseKey),
            }
        }
    }

    impl TryFrom<&KeyConfirmation> for p384::ecdsa::VerifyingKey {
        type Error = error::CoseKeyConfirmationError;

        fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
            Ok(Self::from(p384::PublicKey::try_from(cnf)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::KeyConfirmation;
    use ciborium::{Value, cbor};
    use cose_key_thumbprint::CoseKeyThumbprint;
    use coset::iana;
    use esdicawt_spec::CwtAny as _;
    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    // see https://www.rfc-editor.org/rfc/rfc8747#name-representation-of-an-asymme
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_support_cose_key() {
        let (cose_key, x, y) = {
            let x = hex::decode("d7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9e354089bbe13").unwrap();
            let y = hex::decode("f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e79a3b4e47120").unwrap();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone()).build();
            let key = cose_key::CoseKey::from(key);
            (key, Value::Bytes(x), Value::Bytes(y))
        };
        let cnf = KeyConfirmation::CoseKey(cose_key.clone());
        let expected = cbor!({
            /*COSE_Key*/ 1 => {
                /*kty*/ 1 => /*EC2*/ 2,
                /*crv*/ -1 => /*P-256*/ 1,
                /*x*/ -2 => x,
                /*y*/ -3 => y,
            }
        });
        let expected = expected.unwrap().to_cbor_bytes().unwrap();

        assert_eq!(cnf.to_cbor_bytes().unwrap(), expected);

        // we should have the same outcome when using the p256::PublicKey
        let pk = p256::PublicKey::try_from(cose_key).unwrap();
        let cnf = KeyConfirmation::try_from(&pk).unwrap();
        assert_eq!(cnf.to_cbor_bytes().unwrap(), expected);
    }

    // see https://datatracker.ietf.org/doc/html/rfc9679#section-5.6-4
    #[test]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn should_support_thumbprint() {
        let (cose_key, expected_thumbprint) = {
            let x = hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d").unwrap();
            let y = hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c").unwrap();
            let kid = hex::decode("496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec").unwrap();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x, y).key_id(kid.clone()).build();
            (cose_key::CoseKey::from(key), Value::Bytes(kid))
        };
        let thumbprint = CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(cose_key.clone()).unwrap();
        let cnf = KeyConfirmation::Thumbprint(thumbprint);
        let expected = cbor!({
            /*COSE_Key_Thumbprint*/ 5 => expected_thumbprint
        });
        let expected = expected.unwrap().to_cbor_bytes().unwrap();

        assert_eq!(cnf.to_cbor_bytes().unwrap(), expected);

        // we should have the same outcome when using the p256::PublicKey
        let pk = p256::PublicKey::try_from(cose_key).unwrap();
        let cnf = KeyConfirmation::new_thumbprint(pk).unwrap();
        assert_eq!(cnf.to_cbor_bytes().unwrap(), expected);
    }
}
