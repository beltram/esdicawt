mod codec;
mod error;

#[cfg(feature = "deterministic-encoding")]
pub use codec::deterministic_encoding::{CborDeterministicEncoded, DeterministicEncodingError};
pub use error::CoseKeyError;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKey(coset::CoseKey);

/// Accessors
impl CoseKey {
    pub fn into_inner(self) -> coset::CoseKey {
        self.0
    }
}

impl std::ops::Deref for CoseKey {
    type Target = coset::CoseKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<coset::CoseKey> for CoseKey {
    fn from(k: coset::CoseKey) -> Self {
        Self(k)
    }
}

impl From<CoseKey> for coset::CoseKey {
    fn from(k: CoseKey) -> Self {
        k.0
    }
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::*;
    use coset::iana::{self, EnumI64 as _};

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
    impl From<&ed25519_dalek::VerifyingKey> for CoseKey {
        fn from(pk: &ed25519_dalek::VerifyingKey) -> Self {
            let key = coset::CoseKeyBuilder::new_okp_key()
                .algorithm(iana::Algorithm::EdDSA)
                .param(iana::OkpKeyParameter::X.to_i64(), ciborium::Value::Bytes(pk.as_bytes().into()))
                .param(iana::OkpKeyParameter::Crv.to_i64(), ciborium::Value::Integer(iana::EllipticCurve::Ed25519.to_i64().into()))
                .build();
            Self(key)
        }
    }

    impl From<ed25519_dalek::VerifyingKey> for CoseKey {
        fn from(pk: ed25519_dalek::VerifyingKey) -> Self {
            (&pk).into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&CoseKey> for ed25519_dalek::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
            let coset::CoseKey { alg: Some(alg), params, kty, .. } = &key.0 else {
                return Err(CoseKeyError::MissingAlg);
            };

            // verify kty
            if kty != &coset::KeyType::Assigned(iana::KeyType::OKP) {
                return Err(CoseKeyError::InvalidKty);
            }

            // verify alg
            let coset::Algorithm::Assigned(alg) = alg else {
                return Err(CoseKeyError::UnknownAlg(alg.clone()));
            };
            if *alg != iana::Algorithm::EdDSA {
                return Err(CoseKeyError::InvalidAlg(iana::Algorithm::EdDSA.to_i64(), alg.to_i64()));
            }

            // verify curve
            let Some((_, ciborium::Value::Integer(crv))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::OkpKeyParameter::Crv.to_i64())) else {
                return Err(CoseKeyError::MissingCrv);
            };
            let crv: i64 = (*crv).try_into().map_err(CoseKeyError::InvalidCborIntegerClaimKey)?;

            if crv != iana::EllipticCurve::Ed25519.to_i64() {
                return Err(CoseKeyError::UnknownCurve(crv));
            }

            // read x
            let Some((_, ciborium::Value::Bytes(x))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::OkpKeyParameter::X.to_i64())) else {
                return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
            };
            let x = x[..].try_into().map_err(|_| CoseKeyError::InvalidKeyLength(ed25519_dalek::PUBLIC_KEY_LENGTH, x.len()))?;
            Ok(Self::from_bytes(x)?)
        }
    }

    impl TryFrom<CoseKey> for ed25519_dalek::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
            (&key).try_into()
        }
    }
}

#[cfg(feature = "p256")]
pub mod ec_p256 {
    use super::*;
    use coset::iana::{self, EnumI64 as _};

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
    impl TryFrom<&p256::PublicKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(pk: &p256::PublicKey) -> Result<Self, Self::Error> {
            use p256::elliptic_curve::sec1::ToEncodedPoint as _;
            let point = pk.to_encoded_point(false);
            let (x, y) = (point.x().ok_or(Self::Error::InvalidP256Key)?, point.y().ok_or(Self::Error::InvalidP256Key)?);
            Ok(Self(coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec()).build()))
        }
    }

    impl TryFrom<p256::PublicKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(pk: p256::PublicKey) -> Result<Self, Self::Error> {
            (&pk).try_into()
        }
    }

    impl TryFrom<&p256::ecdsa::VerifyingKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(vk: &p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            let point = vk.to_encoded_point(false);
            let (x, y) = (point.x().ok_or(Self::Error::InvalidP256Key)?, point.y().ok_or(Self::Error::InvalidP256Key)?);
            Ok(Self(
                coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_256, x.to_vec(), y.to_vec())
                    .algorithm(iana::Algorithm::ES256)
                    .build(),
            ))
        }
    }

    impl TryFrom<p256::ecdsa::VerifyingKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(vk: p256::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            (&vk).try_into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&CoseKey> for p256::PublicKey {
        type Error = CoseKeyError;

        fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
            let coset::CoseKey { params, kty, .. } = &key.0;

            // verify kty
            if kty != &coset::KeyType::Assigned(iana::KeyType::EC2) {
                return Err(CoseKeyError::InvalidKty);
            }

            // verify curve
            let Some((_, ciborium::Value::Integer(crv))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64())) else {
                return Err(CoseKeyError::MissingCrv);
            };
            let crv: i64 = (*crv).try_into().map_err(CoseKeyError::InvalidCborIntegerClaimKey)?;

            if crv != iana::EllipticCurve::P_256.to_i64() {
                return Err(CoseKeyError::UnknownCurve(crv));
            }

            // read x & y
            let Some((_, ciborium::Value::Bytes(x))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::X.to_i64())) else {
                return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
            };

            let Some((_, ciborium::Value::Bytes(y))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64())) else {
                return Err(CoseKeyError::MissingPoint("Missing 'y' claim"));
            };

            use p256::elliptic_curve::Curve as _;
            const VERIFYING_KEY_LENGTH: usize = p256::NistP256::ORDER.bits() / 8;

            #[allow(clippy::unnecessary_fallible_conversions)]
            let x = x[..].try_into().map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
            #[allow(clippy::unnecessary_fallible_conversions)]
            let y = y[..].try_into().map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;

            use p256::elliptic_curve::sec1::FromEncodedPoint as _;

            let point = p256::EncodedPoint::from_affine_coordinates(x, y, false);
            Ok(Self::from_encoded_point(&point).into_option().ok_or(CoseKeyError::InvalidP256Key)?)
        }
    }

    impl TryFrom<CoseKey> for p256::PublicKey {
        type Error = CoseKeyError;

        fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
            (&key).try_into()
        }
    }

    impl TryFrom<&CoseKey> for p256::ecdsa::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
            let coset::CoseKey { alg: Some(alg), .. } = &key.0 else {
                return Err(CoseKeyError::MissingAlg);
            };

            // verify alg
            let coset::Algorithm::Assigned(alg) = alg else {
                return Err(CoseKeyError::UnknownAlg(alg.clone()));
            };
            if *alg != iana::Algorithm::ES256 {
                return Err(CoseKeyError::InvalidAlg(iana::Algorithm::ES256.to_i64(), alg.to_i64()));
            }

            Ok(Self::from(p256::PublicKey::try_from(key)?))
        }
    }

    impl TryFrom<CoseKey> for p256::ecdsa::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
            (&key).try_into()
        }
    }
}

#[cfg(feature = "p384")]
pub mod ec_p384 {
    use super::*;
    use coset::iana::{self, EnumI64 as _};

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
    impl TryFrom<&p384::PublicKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(pk: &p384::PublicKey) -> Result<Self, Self::Error> {
            use p384::elliptic_curve::sec1::ToEncodedPoint as _;
            let point = pk.to_encoded_point(false);
            let (x, y) = (point.x().ok_or(Self::Error::InvalidP384Key)?, point.y().ok_or(Self::Error::InvalidP384Key)?);
            Ok(CoseKey(coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_384, x.to_vec(), y.to_vec()).build()))
        }
    }

    impl TryFrom<p384::PublicKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(pk: p384::PublicKey) -> Result<Self, Self::Error> {
            (&pk).try_into()
        }
    }

    impl TryFrom<&p384::ecdsa::VerifyingKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(vk: &p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            let point = vk.to_encoded_point(false);
            let (x, y) = (point.x().ok_or(Self::Error::InvalidP384Key)?, point.y().ok_or(Self::Error::InvalidP384Key)?);
            Ok(CoseKey(
                coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_384, x.to_vec(), y.to_vec())
                    .algorithm(iana::Algorithm::ES384)
                    .build(),
            ))
        }
    }

    impl TryFrom<p384::ecdsa::VerifyingKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(vk: p384::ecdsa::VerifyingKey) -> Result<Self, Self::Error> {
            (&vk).try_into()
        }
    }

    /// Only when [KeyConfirmation] is a [KeyConfirmation::CoseKey]
    impl TryFrom<&CoseKey> for p384::PublicKey {
        type Error = CoseKeyError;

        fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
            let coset::CoseKey { params, kty, .. } = &key.0;

            // verify kty
            if kty != &coset::KeyType::Assigned(iana::KeyType::EC2) {
                return Err(CoseKeyError::InvalidKty);
            }

            // verify curve
            let Some((_, ciborium::Value::Integer(crv))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::Crv.to_i64())) else {
                return Err(CoseKeyError::MissingCrv);
            };
            let crv: i64 = (*crv).try_into().map_err(CoseKeyError::InvalidCborIntegerClaimKey)?;

            if crv != iana::EllipticCurve::P_384.to_i64() {
                return Err(CoseKeyError::UnknownCurve(crv));
            }

            // read x & y
            let Some((_, ciborium::Value::Bytes(x))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::X.to_i64())) else {
                return Err(CoseKeyError::MissingPoint("Missing 'x' claim"));
            };

            let Some((_, ciborium::Value::Bytes(y))) = params.iter().find(|(k, _)| k == &coset::Label::Int(iana::Ec2KeyParameter::Y.to_i64())) else {
                return Err(CoseKeyError::MissingPoint("Missing 'y' claim"));
            };

            use p384::elliptic_curve::Curve as _;
            const VERIFYING_KEY_LENGTH: usize = p384::NistP384::ORDER.bits() / 8;

            #[allow(clippy::unnecessary_fallible_conversions)]
            let x = x[..].try_into().map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, x.len()))?;
            #[allow(clippy::unnecessary_fallible_conversions)]
            let y = y[..].try_into().map_err(|_| CoseKeyError::InvalidKeyLength(VERIFYING_KEY_LENGTH, y.len()))?;

            use p384::elliptic_curve::sec1::FromEncodedPoint as _;

            let point = p384::EncodedPoint::from_affine_coordinates(x, y, false);
            Ok(Self::from_encoded_point(&point).into_option().ok_or(CoseKeyError::InvalidP384Key)?)
        }
    }

    impl TryFrom<CoseKey> for p384::PublicKey {
        type Error = CoseKeyError;

        fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
            (&key).try_into()
        }
    }

    impl TryFrom<&CoseKey> for p384::ecdsa::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: &CoseKey) -> Result<Self, Self::Error> {
            let coset::CoseKey { alg: Some(alg), .. } = &key.0 else {
                return Err(CoseKeyError::MissingAlg);
            };

            // verify alg
            let coset::Algorithm::Assigned(alg) = alg else {
                return Err(CoseKeyError::UnknownAlg(alg.clone()));
            };
            if *alg != iana::Algorithm::ES384 {
                return Err(CoseKeyError::InvalidAlg(iana::Algorithm::ES384.to_i64(), alg.to_i64()));
            }

            Ok(Self::from(p384::PublicKey::try_from(key)?))
        }
    }

    impl TryFrom<CoseKey> for p384::ecdsa::VerifyingKey {
        type Error = CoseKeyError;

        fn try_from(key: CoseKey) -> Result<Self, Self::Error> {
            (&key).try_into()
        }
    }
}
