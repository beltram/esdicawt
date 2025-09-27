use ciborium::Value;
use cose_key::CborDeterministicEncoded;

mod error;

pub use error::CoseKeyThumbprintError;

/// A COSE Key Thumbprint as defined in [RFC 9679](https://datatracker.ietf.org/doc/html/rfc9679)
#[derive(Debug, Copy, Clone, Hash, serde::Serialize, serde::Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct CoseKeyThumbprint<const N: usize = 32>(#[serde(with = "serde_bytes")] [u8; N]);

impl<const N: usize> subtle::ConstantTimeEq for CoseKeyThumbprint<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for CoseKeyThumbprint {
    fn eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        self.ct_eq(other).into()
    }
}

impl<const N: usize> std::fmt::Display for CoseKeyThumbprint<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl<const N: usize> std::ops::Deref for CoseKeyThumbprint<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

macro_rules! thumbprint_compute {
    ($length:literal, $size:ty) => {
        impl CoseKeyThumbprint<$length> {
            /// Will hash either a [cose_key::CoseKey] or a verifying key (ed25519, p256, p384 all
            /// supported via features) with the provided hasher
            pub fn compute<Hasher>(key: impl TryInto<cose_key::CoseKey, Error: Into<error::CoseKeyThumbprintError>>) -> Result<Self, error::CoseKeyThumbprintError>
            where
                Hasher: digest::Digest + digest::OutputSizeUser<OutputSize = $size>,
            {
                let cbor_encoded = Self::_compute(key)?;

                // Hash the bytes produced in step 2 with a cryptographic hash function H
                // see https://datatracker.ietf.org/doc/html/rfc9679#section-3-2.3.1
                let hash = Hasher::digest(&cbor_encoded[..]);

                Ok(Self(hash.into()))
            }
        }
    };
}

thumbprint_compute!(32, digest::typenum::U32);
thumbprint_compute!(48, digest::typenum::U48);
thumbprint_compute!(64, digest::typenum::U64);

impl<const N: usize> CoseKeyThumbprint<N> {
    fn _compute(key: impl TryInto<cose_key::CoseKey, Error: Into<error::CoseKeyThumbprintError>>) -> Result<Vec<u8>, error::CoseKeyThumbprintError> {
        use coset::iana::{self, EnumI64 as _};

        let key: cose_key::CoseKey = key.try_into().map_err(Into::into)?;

        let mut value = Value::serialized(&key)?;
        let Some(claims) = value.as_map_mut() else {
            return Err(error::CoseKeyThumbprintError::InvalidCoseKey);
        };

        // Construct a COSE_Key structure (see Section 7 of [RFC9052]) containing only the required parameters representing the key
        // see https://datatracker.ietf.org/doc/html/rfc9679#section-3-2.1.1
        claims.retain(|(k, _)| match k {
            Value::Integer(i) => {
                let Ok(i) = i64::try_from(*i) else { return false };

                // we keep the kty all the time
                if iana::KeyParameter::from_i64(i) == Some(iana::KeyParameter::Kty) {
                    return true;
                }

                match &key.kty {
                    coset::KeyType::Assigned(iana::KeyType::OKP) => {
                        let Some(param) = iana::OkpKeyParameter::from_i64(i) else {
                            return false;
                        };
                        match param {
                            // see https://datatracker.ietf.org/doc/html/rfc9679#section-4.1
                            iana::OkpKeyParameter::Crv | iana::OkpKeyParameter::X => true,
                            _ => false,
                        }
                    }
                    coset::KeyType::Assigned(iana::KeyType::EC2) => {
                        let Some(param) = iana::Ec2KeyParameter::from_i64(i) else {
                            return false;
                        };
                        match param {
                            // see https://datatracker.ietf.org/doc/html/rfc9679#section-4.2
                            iana::Ec2KeyParameter::Crv | iana::Ec2KeyParameter::X | iana::Ec2KeyParameter::Y => true,
                            _ => false,
                        }
                    }
                    coset::KeyType::Assigned(iana::KeyType::RSA) => {
                        let Some(param) = iana::RsaKeyParameter::from_i64(i) else {
                            return false;
                        };
                        match param {
                            // see https://datatracker.ietf.org/doc/html/rfc9679#section-4.3
                            iana::RsaKeyParameter::N | iana::RsaKeyParameter::E => true,
                            _ => false,
                        }
                    }
                    coset::KeyType::Assigned(iana::KeyType::Symmetric) => {
                        let Some(param) = iana::SymmetricKeyParameter::from_i64(i) else {
                            return false;
                        };
                        match param {
                            // see https://datatracker.ietf.org/doc/html/rfc9679#section-4.4
                            iana::SymmetricKeyParameter::K => true,
                            _ => false,
                        }
                    }
                    coset::KeyType::Assigned(iana::KeyType::HSS_LMS) => {
                        let Some(param) = iana::HssLmsKeyParameter::from_i64(i) else {
                            return false;
                        };
                        match param {
                            // see https://datatracker.ietf.org/doc/html/rfc9679#section-4.5
                            iana::HssLmsKeyParameter::Pub => true,
                            _ => false,
                        }
                    }
                    _ => false,
                }
            }
            _ => false,
        });

        // Apply the deterministic encoding described in Section 4.2.1 of [RFC8949]
        // see https://datatracker.ietf.org/doc/html/rfc9679#section-3-2.2.1
        let cbor_encoded = value.deterministically_serialize()?;

        Ok(cbor_encoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cose_key::CoseKey;
    use coset::iana;

    // see https://datatracker.ietf.org/doc/html/rfc9679#section-6
    #[test]
    fn should_pass_rfc_example() {
        // First let's verify we got the right input CoseKey
        let cose_key = {
            let x = hex::decode("65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c08551d").unwrap();
            let y = hex::decode("1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd0084d19c").unwrap();
            let kid = hex::decode("496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec").unwrap();
            let key = coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.clone(), y.clone())
                .key_id(kid.clone())
                .build();
            cose_key::CoseKey::from(key)
        };

        let key: p256::PublicKey = cose_key.clone().try_into().unwrap();

        // Now computing the thumbprint
        let thumbprint = CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(&key).unwrap();

        let expected_thumbprint = "496bd8afadf307e5b08c64b0421bf9dc01528a344a43bda88fadd1669da253ec";

        assert_eq!(&thumbprint.to_string(), expected_thumbprint);

        // Should be the same outcome when providing a raw CoseKey
        let thumbprint = CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(cose_key).unwrap();
        assert_eq!(&thumbprint.to_string(), expected_thumbprint);
    }

    /// should just compile to make sure the thumbprint length matches the supplied hasher output size
    /// see https://datatracker.ietf.org/doc/html/rfc9679#section-5.2
    #[allow(dead_code)]
    fn supported_hashers_should_compile() {
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(any_cose_key()).unwrap();
        CoseKeyThumbprint::<32>::compute::<sha2::Sha512_256>(any_cose_key()).unwrap();
        CoseKeyThumbprint::<48>::compute::<sha2::Sha384>(any_cose_key()).unwrap();
        CoseKeyThumbprint::<64>::compute::<sha2::Sha512>(any_cose_key()).unwrap();
    }

    /// should just compile
    #[allow(dead_code)]
    fn api_should_be_versatile() {
        // ... and accept either a CoseKey or a verifying key

        // owned CoseKey
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(any_cose_key()).unwrap();

        // owned coset::CoseKey
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(any_coset_cose_key()).unwrap();

        // borrowed ed25519 keys
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(&sk.verifying_key()).unwrap();

        // borrowed ecdsa keys
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(sk.verifying_key()).unwrap();
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(sk.verifying_key()).unwrap();

        // borrowed ec keys
        let sk = p256::SecretKey::random(&mut rand::thread_rng());
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(sk.public_key()).unwrap();
        let sk = p384::SecretKey::random(&mut rand::thread_rng());
        CoseKeyThumbprint::<32>::compute::<sha2::Sha256>(sk.public_key()).unwrap();
    }

    fn any_cose_key() -> CoseKey {
        any_coset_cose_key().into()
    }

    fn any_coset_cose_key() -> coset::CoseKey {
        coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, vec![], vec![]).build()
    }
}
