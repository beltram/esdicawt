mod codec;
mod error;

use ciborium::Value;
#[cfg(feature = "deterministic-encoding")]
pub use codec::deterministic_encoding::{CborDeterministicEncoded, DeterministicEncodingError};
use coset::{Algorithm, KeyOperation, KeyType, Label, iana, iana::EnumI64};
pub use error::CoseKeyError;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CoseKey(coset::CoseKey);

impl std::hash::Hash for CoseKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match &self.kty {
            KeyType::Assigned(i) => i.to_i64().hash(state),
            KeyType::Text(s) => s.hash(state),
        };
        self.key_id.hash(state);
        match &self.alg {
            Some(Algorithm::PrivateUse(i)) => i.hash(state),
            Some(Algorithm::Assigned(i)) => i.to_i64().hash(state),
            Some(Algorithm::Text(s)) => s.hash(state),
            None => {}
        }
        for ops in &self.key_ops {
            match ops {
                KeyOperation::Assigned(i) => i.to_i64().hash(state),
                KeyOperation::Text(s) => s.hash(state),
            }
        }
        self.base_iv.hash(state);
        for (label, value) in &self.params {
            match label {
                Label::Int(i) => i.hash(state),
                Label::Text(s) => s.hash(state),
            }
            hash_value(value, state);
        }
    }
}

// SAFETY: so far no float has been IANA registered (could be for private use though). So it's kinda fine to do this.
impl Eq for CoseKey {}

fn hash_value<H: std::hash::Hasher>(value: &Value, state: &mut H) {
    use std::hash::Hash as _;
    match value {
        Value::Integer(i) => {
            let _ = i64::try_from(*i).inspect(|i| i.hash(state));
        }
        Value::Bytes(b) => {
            b.hash(state);
        }
        Value::Float(f) => f.to_be_bytes().hash(state),
        Value::Text(s) => s.hash(state),
        Value::Bool(b) => b.hash(state),
        Value::Tag(tag, v) => {
            tag.hash(state);
            hash_value(v, state);
        }
        Value::Array(array) => {
            for e in array {
                hash_value(e, state);
            }
        }
        Value::Map(map) => {
            for (k, v) in map {
                hash_value(k, state);
                hash_value(v, state);
            }
        }
        Value::Simple(s) => s.hash(state),
        _ => {}
    };
}

/// Accessors
impl CoseKey {
    pub fn into_inner(self) -> coset::CoseKey {
        self.0
    }

    pub fn alg(&self) -> Option<iana::Algorithm> {
        self.alg.as_ref().and_then(|a| match a {
            Algorithm::Assigned(i) => iana::Algorithm::from_i64(i.to_i64()),
            _ => None,
        })
    }

    pub fn crv(&self) -> Option<iana::EllipticCurve> {
        self.params
            .iter()
            .find_map(|(k, v)| matches!(k, Label::Int(i) if *i == iana::OkpKeyParameter::Crv.to_i64()).then_some(v))
            .and_then(Value::as_integer)
            .and_then(|i| i64::try_from(i).ok())
            .and_then(iana::EllipticCurve::from_i64)
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

pub trait CoseKeyExt {
    fn alg() -> iana::Algorithm;
}

pub trait EcdsaCoseKeyExt: CoseKeyExt {
    fn crv() -> iana::EllipticCurve;
}

#[cfg(feature = "ed25519")]
pub mod ed25519 {
    use super::*;
    use coset::iana::{self};

    impl CoseKeyExt for ed25519_dalek::VerifyingKey {
        fn alg() -> iana::Algorithm {
            iana::Algorithm::EdDSA
        }
    }

    impl EcdsaCoseKeyExt for ed25519_dalek::VerifyingKey {
        fn crv() -> iana::EllipticCurve {
            iana::EllipticCurve::Ed25519
        }
    }

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.2
    impl From<&ed25519_dalek::VerifyingKey> for CoseKey {
        fn from(pk: &ed25519_dalek::VerifyingKey) -> Self {
            Self(
                coset::CoseKeyBuilder::new_okp_key()
                    .algorithm(iana::Algorithm::EdDSA)
                    .param(iana::OkpKeyParameter::X.to_i64(), ciborium::Value::Bytes(pk.as_bytes().into()))
                    .param(iana::OkpKeyParameter::Crv.to_i64(), ciborium::Value::Integer(iana::EllipticCurve::Ed25519.to_i64().into()))
                    .build(),
            )
        }
    }

    impl From<ed25519_dalek::VerifyingKey> for CoseKey {
        fn from(pk: ed25519_dalek::VerifyingKey) -> Self {
            (&pk).into()
        }
    }

    impl From<&ed25519_dalek::SigningKey> for CoseKey {
        fn from(sk: &ed25519_dalek::SigningKey) -> Self {
            sk.verifying_key().into()
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
    use coset::iana::{self};

    impl CoseKeyExt for p256::ecdsa::VerifyingKey {
        fn alg() -> iana::Algorithm {
            iana::Algorithm::ES256
        }
    }

    impl EcdsaCoseKeyExt for p256::ecdsa::VerifyingKey {
        fn crv() -> iana::EllipticCurve {
            iana::EllipticCurve::P_256
        }
    }

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

    impl TryFrom<&p256::ecdsa::SigningKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(sk: &p256::ecdsa::SigningKey) -> Result<Self, Self::Error> {
            sk.as_ref().try_into()
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
            Self::from_encoded_point(&point).into_option().ok_or(CoseKeyError::InvalidP256Key)
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
    use coset::iana::{self};

    impl CoseKeyExt for p384::ecdsa::VerifyingKey {
        fn alg() -> iana::Algorithm {
            iana::Algorithm::ES384
        }
    }

    impl EcdsaCoseKeyExt for p384::ecdsa::VerifyingKey {
        fn crv() -> iana::EllipticCurve {
            iana::EllipticCurve::P_384
        }
    }

    /// See https://datatracker.ietf.org/doc/html/rfc8152#section-8.1
    impl TryFrom<&p384::PublicKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(pk: &p384::PublicKey) -> Result<Self, Self::Error> {
            use p384::elliptic_curve::sec1::ToEncodedPoint as _;
            let point = pk.to_encoded_point(false);
            let (x, y) = (point.x().ok_or(Self::Error::InvalidP384Key)?, point.y().ok_or(Self::Error::InvalidP384Key)?);
            Ok(Self(coset::CoseKeyBuilder::new_ec2_pub_key(iana::EllipticCurve::P_384, x.to_vec(), y.to_vec()).build()))
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
            Ok(Self(
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

    impl TryFrom<&p384::ecdsa::SigningKey> for CoseKey {
        type Error = CoseKeyError;

        fn try_from(sk: &p384::ecdsa::SigningKey) -> Result<Self, Self::Error> {
            sk.as_ref().try_into()
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
            Self::from_encoded_point(&point).into_option().ok_or(CoseKeyError::InvalidP384Key)
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

#[cfg(feature = "pem")]
impl CoseKey {
    #[allow(dead_code)]
    pub fn from_public_key_pem(s: &str) -> pkcs8::spki::Result<Self> {
        let (_, doc) = pkcs8::Document::from_pem(s)?;
        Self::from_public_key_der(doc.as_bytes())
    }

    #[allow(dead_code, unreachable_code)]
    pub fn from_public_key_der(#[allow(unused_variables)] bytes: &[u8]) -> pkcs8::spki::Result<Self> {
        use pkcs8::DecodePublicKey as _;
        #[cfg(all(feature = "ed25519", feature = "p256", feature = "p384"))]
        {
            let ck = ed25519_dalek::VerifyingKey::from_public_key_der(bytes).map(Into::into);
            let ck = ck.or_else(|_| p256::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed)));
            let ck = ck.or_else(|_| p384::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed)));
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(all(feature = "ed25519", feature = "p256"))]
        {
            let ck = ed25519_dalek::VerifyingKey::from_public_key_der(bytes).map(Into::into);
            let ck = ck.or_else(|_| p256::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed)));
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(all(feature = "ed25519", feature = "p384"))]
        {
            let ck = ed25519_dalek::VerifyingKey::from_public_key_der(bytes).map(Into::into);
            let ck = ck.or_else(|_| p384::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed)));
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(all(feature = "p256", feature = "p384"))]
        {
            let ck = p256::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed));
            let ck = ck.or_else(|_| p384::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed)));
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(feature = "ed25519")]
        {
            let ck = ed25519_dalek::VerifyingKey::from_public_key_der(bytes).map(Into::into);
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(feature = "p256")]
        {
            let ck = p256::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed));
            return ck.map_err(|_| pkcs8::spki::Error::KeyMalformed);
        }
        #[cfg(feature = "p384")]
        {
            let ck = p384::ecdsa::VerifyingKey::from_public_key_der(bytes).and_then(|vk| Self::try_from(vk).map_err(|_| pkcs8::spki::Error::KeyMalformed));
            ck.map_err(|_| pkcs8::spki::Error::KeyMalformed)
        }
        #[cfg(not(any(feature = "ed25519", feature = "p256", feature = "p384")))]
        {
            return Err(pkcs8::spki::Error::KeyMalformed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pkcs8::{EncodePublicKey, LineEnding::LF};

    #[test]
    fn from_pem_should_succeed() {
        // Ed25519
        let vk = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng()).verifying_key();
        let ck = CoseKey::from(&vk);

        let pem = vk.to_public_key_pem(LF).unwrap();
        let ck_pem = CoseKey::from_public_key_pem(&pem).unwrap();
        assert_eq!(ck, ck_pem);

        // P256
        let sk = p256::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let vk = sk.as_ref();
        let ck = CoseKey::try_from(vk).unwrap();

        let pem = vk.to_public_key_pem(LF).unwrap();
        let ck_pem = CoseKey::from_public_key_pem(&pem).unwrap();
        assert_eq!(ck, ck_pem);

        // P384
        let sk = p384::ecdsa::SigningKey::random(&mut rand::thread_rng());
        let vk = sk.as_ref();
        let ck = CoseKey::try_from(vk).unwrap();

        let pem = vk.to_public_key_pem(LF).unwrap();
        let ck_pem = CoseKey::from_public_key_pem(&pem).unwrap();
        assert_eq!(ck, ck_pem);
    }
}
