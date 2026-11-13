//! Keys of any algorithm supported by the interop test cases, chosen at runtime from the PEM files given on the
//! command line. esdicawt's traits take a single signer/verifier type, so these enums dispatch to the right one.

use esdicawt::{
    cose_key::{
        CoseKey,
        confirmation::{CoseKeyConfirmationError, KeyConfirmation},
        keyset::CoseKeySet,
    },
    coset::iana::Algorithm,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use std::path::Path;

#[derive(Clone)]
pub enum AnySigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
}

impl AnySigningKey {
    pub fn from_pem_file(path: &Path) -> eyre::Result<Self> {
        let pem = std::fs::read_to_string(path).map_err(|e| eyre::eyre!("cannot read private key '{}': {e}", path.display()))?;
        Self::from_pem(&pem).ok_or_else(|| eyre::eyre!("'{}' is not an Ed25519, P-256 or P-384 private key (PKCS#8 or SEC1 PEM)", path.display()))
    }

    pub fn from_pem(pem: &str) -> Option<Self> {
        let pem = pem.trim();
        if let Ok(k) = ed25519_dalek::SigningKey::from_pkcs8_pem(pem) {
            return Some(Self::Ed25519(k));
        }
        if let Ok(k) = p256::SecretKey::from_pkcs8_pem(pem).or_else(|_| p256::SecretKey::from_sec1_pem(pem)) {
            return Some(Self::P256(k.into()));
        }
        if let Ok(k) = p384::SecretKey::from_pkcs8_pem(pem).or_else(|_| p384::SecretKey::from_sec1_pem(pem)) {
            return Some(Self::P384(k.into()));
        }
        None
    }

    pub const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::EdDSA,
            Self::P256(_) => Algorithm::ES256,
            Self::P384(_) => Algorithm::ES384,
        }
    }
}

impl signature::Signer<AnySignature> for AnySigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<AnySignature, signature::Error> {
        Ok(AnySignature(match self {
            Self::Ed25519(k) => signature::Signer::<ed25519_dalek::Signature>::try_sign(k, msg)?.to_bytes().to_vec(),
            Self::P256(k) => signature::Signer::<p256::ecdsa::Signature>::try_sign(k, msg)?.to_bytes().to_vec(),
            Self::P384(k) => signature::Signer::<p384::ecdsa::Signature>::try_sign(k, msg)?.to_bytes().to_vec(),
        }))
    }
}

impl signature::Keypair for AnySigningKey {
    type VerifyingKey = AnyVerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        match self {
            Self::Ed25519(k) => k.verifying_key().into(),
            Self::P256(k) => (*k.verifying_key()).into(),
            Self::P384(k) => (*k.verifying_key()).into(),
        }
    }
}

/// A public key along with its encoding, the latter required by esdicawt's Verifier (`AsRef<[u8]>`)
#[derive(Debug, Clone)]
pub struct AnyVerifyingKey {
    key: VerifyingKeyKind,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifyingKeyKind {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
}

impl PartialEq for AnyVerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl From<ed25519_dalek::VerifyingKey> for AnyVerifyingKey {
    fn from(k: ed25519_dalek::VerifyingKey) -> Self {
        Self {
            bytes: k.as_bytes().to_vec(),
            key: VerifyingKeyKind::Ed25519(k),
        }
    }
}

impl From<p256::ecdsa::VerifyingKey> for AnyVerifyingKey {
    fn from(k: p256::ecdsa::VerifyingKey) -> Self {
        Self {
            bytes: k.to_sec1_point(false).as_bytes().to_vec(),
            key: VerifyingKeyKind::P256(k),
        }
    }
}

impl From<p384::ecdsa::VerifyingKey> for AnyVerifyingKey {
    fn from(k: p384::ecdsa::VerifyingKey) -> Self {
        Self {
            bytes: k.to_sec1_point(false).as_bytes().to_vec(),
            key: VerifyingKeyKind::P384(k),
        }
    }
}

impl AnyVerifyingKey {
    /// Reads a public key PEM, or derives it from a private key PEM
    pub fn from_pem_file(path: &Path) -> eyre::Result<Self> {
        let pem = std::fs::read_to_string(path).map_err(|e| eyre::eyre!("cannot read public key '{}': {e}", path.display()))?;
        Self::from_pem(&pem).ok_or_else(|| eyre::eyre!("'{}' is not an Ed25519, P-256 or P-384 key (SPKI or PKCS#8 PEM)", path.display()))
    }

    pub fn from_pem(pem: &str) -> Option<Self> {
        let pem = pem.trim();
        if let Ok(k) = ed25519_dalek::VerifyingKey::from_public_key_pem(pem) {
            return Some(k.into());
        }
        if let Ok(k) = p256::PublicKey::from_public_key_pem(pem) {
            return Some(p256::ecdsa::VerifyingKey::from(k).into());
        }
        if let Ok(k) = p384::PublicKey::from_public_key_pem(pem) {
            return Some(p384::ecdsa::VerifyingKey::from(k).into());
        }
        AnySigningKey::from_pem(pem).map(|k| signature::Keypair::verifying_key(&k))
    }

    pub fn to_cose_key(&self) -> eyre::Result<CoseKey> {
        Ok(match &self.key {
            VerifyingKeyKind::Ed25519(k) => CoseKey::try_from(k)?,
            VerifyingKeyKind::P256(k) => CoseKey::try_from(k)?,
            VerifyingKeyKind::P384(k) => CoseKey::try_from(k)?,
        })
    }

    pub fn to_keyset(&self) -> eyre::Result<CoseKeySet> {
        Ok(CoseKeySet::builder().with_cose_key(self.to_cose_key()?)?.build())
    }
}

impl AsRef<[u8]> for AnyVerifyingKey {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl signature::Verifier<AnySignature> for AnyVerifyingKey {
    fn verify(&self, msg: &[u8], signature: &AnySignature) -> Result<(), signature::Error> {
        match &self.key {
            VerifyingKeyKind::Ed25519(k) => k.verify(msg, &ed25519_dalek::Signature::from_slice(&signature.0)?),
            VerifyingKeyKind::P256(k) => k.verify(msg, &p256::ecdsa::Signature::from_slice(&signature.0)?),
            VerifyingKeyKind::P384(k) => k.verify(msg, &p384::ecdsa::Signature::from_slice(&signature.0)?),
        }
    }
}

impl TryFrom<&KeyConfirmation> for AnyVerifyingKey {
    type Error = CoseKeyConfirmationError;

    fn try_from(cnf: &KeyConfirmation) -> Result<Self, Self::Error> {
        if let Ok(k) = ed25519_dalek::VerifyingKey::try_from(cnf) {
            return Ok(k.into());
        }
        if let Ok(k) = p256::ecdsa::VerifyingKey::try_from(cnf) {
            return Ok(k.into());
        }
        p384::ecdsa::VerifyingKey::try_from(cnf).map(Into::into)
    }
}

/// The raw COSE signature bytes, interpreted by [AnyVerifyingKey] according to its algorithm
#[derive(Debug, Clone)]
pub struct AnySignature(Vec<u8>);

impl TryFrom<&[u8]> for AnySignature {
    type Error = signature::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(bytes.to_vec()))
    }
}

impl From<AnySignature> for Vec<u8> {
    fn from(signature: AnySignature) -> Self {
        signature.0
    }
}

impl signature::SignatureEncoding for AnySignature {
    type Repr = Vec<u8>;
}
