//! Raw CBOR helpers to peek into tokens before handing them to esdicawt (kid, AEAD encrypted disclosures, ...)

use crate::KeyFetch;
use ciborium::Value;
use esdicawt::cose_key::keyset::CoseKeySet;
use std::path::Path;

pub const COSE_SIGN1_TAG: u64 = 18;
pub const HEADER_KID: i64 = 4;
pub const HEADER_KCWT: i64 = 13;
pub const HEADER_SD_CLAIMS: i64 = 17;
pub const HEADER_SD_AEAD_ENCRYPTED_CLAIMS: i64 = 171;

/// A feature of INTEROP.md this implementation does not support; exits with a distinct code
#[derive(Debug)]
pub struct Unsupported(pub String);

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported by esdicawt: {}", self.0)
    }
}

impl std::error::Error for Unsupported {}

pub fn unsupported(msg: impl Into<String>) -> eyre::Report {
    Unsupported(msg.into()).into()
}

pub fn read_stdin() -> eyre::Result<Vec<u8>> {
    use std::io::Read as _;
    let mut buf = vec![];
    std::io::stdin().read_to_end(&mut buf)?;
    if buf.is_empty() {
        eyre::bail!("nothing on stdin");
    }
    Ok(buf)
}

pub fn write_stdout(bytes: &[u8]) -> eyre::Result<()> {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(bytes)?;
    stdout.flush()?;
    Ok(())
}

pub fn decode(bytes: &[u8]) -> eyre::Result<Value> {
    Ok(ciborium::from_reader::<Value, _>(bytes)?)
}

pub fn encode(value: &Value) -> eyre::Result<Vec<u8>> {
    let mut buf = vec![];
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

pub fn label_is(label: &Value, expected: i64) -> bool {
    matches!(label, Value::Integer(i) if i128::from(*i) == i128::from(expected))
}

pub fn map_get(map: &[(Value, Value)], label: i64) -> Option<&Value> {
    map.iter().find(|(k, _)| label_is(k, label)).map(|(_, v)| v)
}

/// The headers and payload of a COSE_Sign1, decoded
#[derive(Debug, Clone)]
pub struct Sign1 {
    pub protected: Vec<(Value, Value)>,
    pub unprotected: Vec<(Value, Value)>,
    pub payload: Vec<(Value, Value)>,
}

impl Sign1 {
    pub fn from_bytes(bytes: &[u8]) -> eyre::Result<Self> {
        Self::from_value(decode(bytes)?)
    }

    pub fn from_value(value: Value) -> eyre::Result<Self> {
        let array = match value {
            Value::Tag(COSE_SIGN1_TAG, inner) => *inner,
            Value::Bytes(b) => return Self::from_bytes(&b),
            v => v,
        };
        let Value::Array(array) = array else {
            eyre::bail!("not a COSE_Sign1");
        };
        let mut items = array.into_iter();
        let (Some(Value::Bytes(protected)), Some(Value::Map(unprotected)), Some(payload)) = (items.next(), items.next(), items.next()) else {
            eyre::bail!("not a COSE_Sign1");
        };
        let protected = if protected.is_empty() {
            vec![]
        } else {
            decode(&protected)?.into_map().map_err(|_| eyre::eyre!("protected header is not a map"))?
        };
        let payload = match payload {
            Value::Bytes(b) => decode(&b)?.into_map().map_err(|_| eyre::eyre!("payload is not a map"))?,
            _ => vec![],
        };
        Ok(Self { protected, unprotected, payload })
    }

    /// The SD-CWT embedded in the 'kcwt' header of a SD-KBT
    pub fn kcwt(&self) -> eyre::Result<Self> {
        let kcwt = map_get(&self.protected, HEADER_KCWT).ok_or_else(|| eyre::eyre!("SD-KBT has no 'kcwt' (13) protected header"))?;
        Self::from_value(kcwt.clone())
    }

    pub fn kid(&self) -> Option<Vec<u8>> {
        map_get(&self.protected, HEADER_KID)
            .or_else(|| map_get(&self.unprotected, HEADER_KID))
            .and_then(|kid| match kid {
                Value::Bytes(b) => Some(b.clone()),
                Value::Text(t) => Some(t.as_bytes().to_vec()),
                _ => None,
            })
    }

    pub fn sd_claims(&self) -> Vec<Vec<u8>> {
        match map_get(&self.unprotected, HEADER_SD_CLAIMS) {
            Some(Value::Array(a)) => a.iter().filter_map(|d| d.as_bytes().cloned()).collect(),
            _ => vec![],
        }
    }

    pub fn aead_encrypted_claims(&self) -> usize {
        match map_get(&self.unprotected, HEADER_SD_AEAD_ENCRYPTED_CLAIMS) {
            Some(Value::Array(a)) => a.len(),
            _ => 0,
        }
    }
}

/// The salt of a raw disclosure: the first element of the array
pub fn disclosure_salt(disclosure: &[u8]) -> eyre::Result<Vec<u8>> {
    match decode(disclosure)? {
        Value::Array(a) => match a.into_iter().next() {
            Some(Value::Bytes(salt)) => Ok(salt),
            _ => eyre::bail!("disclosure does not start with a salt"),
        },
        _ => eyre::bail!("disclosure is not an array"),
    }
}

/// Builds the keyset used to verify the Issuer's signature, see the `--issuer` and `--issuer-key` options of INTEROP.md
pub fn issuer_keyset(issuer: Option<&Path>, issuer_key: Option<KeyFetch>, sd_cwt: &Sign1) -> eyre::Result<CoseKeySet> {
    if let Some(issuer) = issuer {
        return crate::keys::AnyVerifyingKey::from_pem_file(issuer)?.to_keyset();
    }
    match issuer_key {
        None => eyre::bail!("no --issuer key given, the Issuer signature cannot be verified"),
        Some(KeyFetch::Ignore) => Err(unsupported("--issuer-key ignore: esdicawt always verifies the Issuer signature, give an --issuer key")),
        Some(KeyFetch::Fetch) => Err(unsupported("--issuer-key fetch: no network fetching of the Issuer key, use --issuer-key cache")),
        Some(KeyFetch::Cache) => {
            let kid = sd_cwt.kid().ok_or_else(|| eyre::eyre!("--issuer-key cache: the SD-CWT has no kid"))?;
            let kid = String::from_utf8(kid).map_err(|_| eyre::eyre!("--issuer-key cache: the kid is not a URL"))?;
            if !kid.starts_with("https:") {
                eyre::bail!("--issuer-key cache: the kid '{kid}' is not an https: URL");
            }
            let filename = kid
                .rsplit('/')
                .next()
                .filter(|f| !f.is_empty())
                .ok_or_else(|| eyre::eyre!("--issuer-key cache: no filename in '{kid}'"))?;
            eprintln!("loading the Issuer key from './{filename}' (kid '{kid}')");
            crate::keys::AnyVerifyingKey::from_pem_file(Path::new(filename))?.to_keyset()
        }
    }
}

/// No `--time` given: the draft's test cases are expired, so time claims are not verified at all
pub fn time_verification(time: Option<u64>) -> esdicawt::TimeVerification {
    match time {
        Some(_) => Default::default(),
        None => {
            eprintln!("no --time given: time claims are not verified");
            esdicawt::TimeVerification {
                verify_exp: false,
                verify_iat: false,
                verify_nbf: false,
            }
        }
    }
}
