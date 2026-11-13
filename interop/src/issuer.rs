use crate::{
    IssueArgs,
    keys::{AnySignature, AnySigningKey},
    token::{Sign1, decode, label_is, read_stdin, unsupported, write_stdout},
};
use ciborium::Value;
use esdicawt::{
    Issuer, IssuerParams, Subject, TimeArg,
    cose_key::confirmation::KeyConfirmation,
    coset,
    spec::{CWT_CLAIM_AUDIENCE, CWT_CLAIM_CNONCE, CWT_CLAIM_CTI, CWT_CLAIM_EXPIRES_AT, CWT_CLAIM_ISSUED_AT, CWT_CLAIM_ISSUER, CWT_CLAIM_KEY_CONFIRMATION, CWT_CLAIM_NOT_BEFORE},
    spec::{CWT_CLAIM_SUBJECT, EsdicawtSpecError, NoClaims, SdHashAlg, TO_BE_DECOY_TAG, TO_BE_REDACTED_TAG},
};
use sha2::Digest as _;
use std::{collections::HashMap, path::Path, time::Duration};

/// Written in the current directory with all the salts used, see INTEROP.md
const NONCE_LIST_OUT: &str = "nonce_list.out";
const SALT_SIZE: usize = 16;
/// Each round of issuance fixes the salts of one more level of nested disclosures
const MAX_ISSUANCE_ROUNDS: usize = 32;

pub fn issue(args: IssueArgs) -> eyre::Result<()> {
    let claims = decode(&read_stdin()?)?;
    let signing_key = AnySigningKey::from_pem_file(&args.issuer_priv)?;
    let nonces = args.nonces.as_deref().map(read_nonces).transpose()?;

    let (sd_cwt, used) = issue_claims(claims, signing_key, &args.kid, nonces.as_ref(), args.time)?;

    let out = used.iter().map(|(k, salt)| format!("{k},{}\n", hex::encode(salt))).collect::<String>();
    std::fs::write(NONCE_LIST_OUT, out)?;
    write_stdout(&sd_cwt)
}

/// Key of a row in the nonce list
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NonceKey {
    /// sha256 of `[key, value]` for a map claim or `[null, value]` for an array element
    Digest([u8; 32]),
    /// the integer in the To Be Decoy tag
    Decoy(u64),
}

impl std::fmt::Display for NonceKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Digest(d) => write!(f, "{}", hex::encode(d)),
            Self::Decoy(i) => write!(f, "{i}"),
        }
    }
}

pub type Nonces = HashMap<NonceKey, [u8; SALT_SIZE]>;

/// The salt of each disclosure of an issued SD-CWT
pub type UsedNonces = Vec<(NonceKey, Vec<u8>)>;

pub fn read_nonces(path: &Path) -> eyre::Result<Nonces> {
    let csv = std::fs::read_to_string(path).map_err(|e| eyre::eyre!("cannot read nonce list '{}': {e}", path.display()))?;
    parse_nonces(&csv)
}

pub fn parse_nonces(csv: &str) -> eyre::Result<Nonces> {
    let mut nonces = Nonces::new();
    for line in csv.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (key, salt) = line.split_once(',').ok_or_else(|| eyre::eyre!("invalid nonce list row '{line}'"))?;
        let (key, salt) = (key.trim(), salt.trim());
        let key = if !key.is_empty() && key.bytes().all(|b| b.is_ascii_digit()) {
            NonceKey::Decoy(key.parse()?)
        } else {
            let digest = hex::decode(key)?;
            NonceKey::Digest(digest.try_into().map_err(|_| eyre::eyre!("'{key}' is not a SHA-256 digest"))?)
        };
        let salt = hex::decode(salt)?;
        let salt = salt.try_into().map_err(|_| eyre::eyre!("esdicawt only supports {SALT_SIZE} bytes salts, got '{line}'"))?;
        nonces.insert(key, salt);
    }
    Ok(nonces)
}

/// The claims set split into the standard claims esdicawt sets itself and the rest of the payload
struct Claims {
    issuer: String,
    subject: (bool, String),
    audience: Option<String>,
    expiry: Option<u64>,
    not_before: Option<u64>,
    issued_at: Option<u64>,
    cti: Option<Vec<u8>>,
    cnonce: Option<Vec<u8>>,
    cnf: KeyConfirmation,
    payload: Vec<(Value, Value)>,
}

impl TryFrom<Value> for Claims {
    type Error = eyre::Report;

    fn try_from(claims: Value) -> eyre::Result<Self> {
        let Value::Map(entries) = claims else {
            eyre::bail!("the claims set is not a CBOR map");
        };
        let as_u64 = |v: &Value, name: &str| -> eyre::Result<u64> {
            v.as_integer()
                .and_then(|i| u64::try_from(i).ok())
                .ok_or_else(|| eyre::eyre!("'{name}' must be a positive integer"))
        };

        let (mut issuer, mut subject, mut audience, mut cnf) = (None, None, None, None);
        let (mut expiry, mut not_before, mut issued_at, mut cti, mut cnonce) = (None, None, None, None, None);
        let mut payload = vec![];
        for (k, v) in entries {
            match (&k, v) {
                (k, Value::Text(s)) if label_is(k, CWT_CLAIM_ISSUER) => issuer = Some(s),
                (k, Value::Text(s)) if label_is(k, CWT_CLAIM_SUBJECT) => subject = Some((false, s)),
                (Value::Tag(TO_BE_REDACTED_TAG, inner), Value::Text(s)) if label_is(inner, CWT_CLAIM_SUBJECT) => subject = Some((true, s)),
                (k, Value::Text(s)) if label_is(k, CWT_CLAIM_AUDIENCE) => audience = Some(s),
                (k, v) if label_is(k, CWT_CLAIM_EXPIRES_AT) => expiry = Some(as_u64(&v, "exp")?),
                (k, v) if label_is(k, CWT_CLAIM_NOT_BEFORE) => not_before = Some(as_u64(&v, "nbf")?),
                (k, v) if label_is(k, CWT_CLAIM_ISSUED_AT) => issued_at = Some(as_u64(&v, "iat")?),
                (k, Value::Bytes(b)) if label_is(k, CWT_CLAIM_CTI) => cti = Some(b),
                (k, Value::Bytes(b)) if label_is(k, CWT_CLAIM_CNONCE) => cnonce = Some(b),
                (k, v) if label_is(k, CWT_CLAIM_KEY_CONFIRMATION) => {
                    cnf = Some(v.deserialized::<KeyConfirmation>().map_err(|e| eyre::eyre!("invalid 'cnf' claim: {e}"))?);
                }
                (k, _)
                    if [CWT_CLAIM_ISSUER, CWT_CLAIM_SUBJECT, CWT_CLAIM_AUDIENCE, CWT_CLAIM_CTI, CWT_CLAIM_CNONCE]
                        .iter()
                        .any(|&l| label_is(k, l)) =>
                {
                    return Err(unsupported(format!("claim {k:?} with this type")));
                }
                (Value::Tag(TO_BE_REDACTED_TAG, inner), _)
                    if [
                        CWT_CLAIM_ISSUER,
                        CWT_CLAIM_EXPIRES_AT,
                        CWT_CLAIM_NOT_BEFORE,
                        CWT_CLAIM_ISSUED_AT,
                        CWT_CLAIM_KEY_CONFIRMATION,
                    ]
                    .iter()
                    .any(|&l| label_is(inner, l)) =>
                {
                    return Err(unsupported(format!("redacting the standard claim {inner:?}")));
                }
                (_, v) => payload.push((k, v)),
            }
        }
        Ok(Self {
            issuer: issuer.ok_or_else(|| eyre::eyre!("the claims set has no 'iss' (1)"))?,
            subject: subject.ok_or_else(|| eyre::eyre!("the claims set has no 'sub' (2), esdicawt requires one"))?,
            audience,
            expiry,
            not_before,
            issued_at,
            cti,
            cnonce,
            cnf: cnf.ok_or_else(|| eyre::eyre!("the claims set has no 'cnf' (8)"))?,
            payload,
        })
    }
}

/// Issues a SD-CWT, returns it along with the salt of each disclosure
pub fn issue_claims(claims: Value, signing_key: AnySigningKey, kid: &str, nonces: Option<&Nonces>, time: Option<u64>) -> eyre::Result<(Vec<u8>, UsedNonces)> {
    let claims = Claims::try_from(claims)?;

    if let Some(now) = time {
        if claims.expiry.is_some_and(|exp| exp <= now) {
            eyre::bail!("the claims set is expired at time {now}");
        }
        if claims.not_before.is_some_and(|nbf| nbf > now) {
            eyre::bail!("the claims set is not yet valid at time {now}");
        }
        if claims.issued_at.is_some_and(|iat| iat > now) {
            eyre::bail!("the claims set is issued in the future of time {now}");
        }
    }

    // esdicawt computes 'iat' and 'nbf' from the issuance time: iat = now, nbf = now - leeway
    let (artificial_time, leeway) = match (claims.issued_at, claims.not_before) {
        (Some(iat), Some(nbf)) if nbf > iat => return Err(unsupported("'nbf' after 'iat'")),
        (Some(iat), Some(nbf)) => (Some(iat), iat - nbf),
        (Some(iat), None) => (Some(iat), 0),
        (None, Some(nbf)) => (Some(nbf), 0),
        (None, None) => (None, 0),
    };
    let decoy_indexes = decoy_indexes(&claims.payload);

    let subject = match claims.subject.0 {
        true => Subject::Redacted(&claims.subject.1),
        false => Subject::Unredacted(&claims.subject.1),
    };
    let params = IssuerParams {
        protected_claims: None,
        unprotected_claims: None,
        payload: (!claims.payload.is_empty()).then(|| Value::Map(claims.payload.clone())),
        issuer: &claims.issuer,
        subject,
        audience: claims.audience.as_deref(),
        expiry: claims.expiry.map(|exp| TimeArg::Absolute(Duration::from_secs(exp))),
        with_not_before: claims.not_before.is_some(),
        with_issued_at: claims.issued_at.is_some(),
        cti: claims.cti.as_deref(),
        cnonce: claims.cnonce.as_deref(),
        artificial_time: artificial_time.map(Duration::from_secs),
        leeway: Duration::from_secs(leeway),
        key_location: kid,
        holder_confirmation_key: claims.cnf.clone(),
    };
    let issuer = CliIssuer { signing_key };

    // the salt of a disclosure depends on its content, which contains the digests of the disclosures nested in it.
    // So the issuance is replayed, fixing at each round the salts of the disclosures whose content is now final
    let mut overrides = HashMap::<usize, [u8; SALT_SIZE]>::new();
    for _ in 0..MAX_ISSUANCE_ROUNDS {
        let mut rng = ScriptedRng::new(overrides.clone());
        let sd_cwt = issuer.issue_raw_cwt(&mut rng, params.clone())?;
        let used = disclosure_nonce_keys(&sd_cwt, &decoy_indexes)?;

        let Some(nonces) = nonces else {
            return Ok((sd_cwt, used));
        };

        let salt_to_draw = rng.drawn.iter().enumerate().map(|(i, s)| (s.as_slice(), i)).collect::<HashMap<_, _>>();
        let next_overrides = used
            .iter()
            .filter_map(|(key, salt)| Some((*salt_to_draw.get(salt.as_slice())?, *nonces.get(key)?)))
            .collect::<HashMap<_, _>>();
        if next_overrides == overrides {
            return Ok((sd_cwt, used));
        }
        overrides = next_overrides;
    }
    eyre::bail!("the salts of the nonce list did not converge after {MAX_ISSUANCE_ROUNDS} issuances")
}

/// Indexes of the To Be Decoy tags, in the order esdicawt creates their disclosures (depth first)
fn decoy_indexes(payload: &[(Value, Value)]) -> Vec<u64> {
    fn walk(value: &Value, out: &mut Vec<u64>) {
        match value {
            Value::Tag(TO_BE_DECOY_TAG, i) => out.extend(i.as_integer().and_then(|i| u64::try_from(i).ok())),
            Value::Tag(_, inner) => walk(inner, out),
            Value::Array(a) => a.iter().for_each(|e| walk(e, out)),
            Value::Map(m) => walk_map(m, out),
            _ => {}
        }
    }
    fn walk_map(map: &[(Value, Value)], out: &mut Vec<u64>) {
        for (k, v) in map {
            match k {
                Value::Tag(TO_BE_DECOY_TAG, _) => walk(k, out),
                _ => walk(v, out),
            }
        }
    }
    let mut out = vec![];
    walk_map(payload, &mut out);
    out
}

/// The nonce list key and the salt of each disclosure of an issued SD-CWT
fn disclosure_nonce_keys(sd_cwt: &[u8], decoy_indexes: &[u64]) -> eyre::Result<UsedNonces> {
    let mut decoys = decoy_indexes.iter();
    let mut out = vec![];
    for disclosure in Sign1::from_bytes(sd_cwt)?.sd_claims() {
        let (salt, preimage) = split_disclosure(&disclosure)?;
        let key = match preimage {
            Some(preimage) => NonceKey::Digest(sha2::Sha256::digest(preimage).into()),
            None => match decoys.next() {
                Some(&i) => NonceKey::Decoy(i),
                None => {
                    eprintln!("cannot find the To Be Decoy index of a decoy");
                    continue;
                }
            },
        };
        out.push((key, salt));
    }
    Ok(out)
}

/// Splits a disclosure into its salt and the CBOR of `[key, value]` (map claim) or `[null, value]` (array element),
/// keeping the bytes of the key and value as is
fn split_disclosure(disclosure: &[u8]) -> eyre::Result<(Vec<u8>, Option<Vec<u8>>)> {
    let (&header, mut rest) = disclosure.split_first().ok_or_else(|| eyre::eyre!("empty disclosure"))?;
    let next = |rest: &mut &[u8]| -> eyre::Result<Vec<u8>> {
        let before = *rest;
        let _ = ciborium::from_reader::<Value, _>(&mut *rest)?;
        Ok(before.get(..before.len() - rest.len()).unwrap_or_default().to_vec())
    };
    let salt = match decode(&next(&mut rest)?)? {
        Value::Bytes(salt) => salt,
        _ => eyre::bail!("disclosure does not start with a salt"),
    };
    const NULL: u8 = 0xf6;
    let preimage = match header {
        0x81 => None,
        0x82 => Some([&[0x82, NULL][..], &next(&mut rest)?].concat()),
        0x83 => {
            let value = next(&mut rest)?;
            let key = next(&mut rest)?;
            Some([&[0x82][..], &key, &value].concat())
        }
        _ => eyre::bail!("unexpected disclosure"),
    };
    Ok((salt, preimage))
}

/// Records the random values drawn by the issuer, and replaces some of them with the ones of the nonce list
struct ScriptedRng {
    overrides: HashMap<usize, [u8; SALT_SIZE]>,
    drawn: Vec<Vec<u8>>,
    rng: rand::rngs::ThreadRng,
}

impl ScriptedRng {
    fn new(overrides: HashMap<usize, [u8; SALT_SIZE]>) -> Self {
        Self {
            overrides,
            drawn: vec![],
            rng: rand::rng(),
        }
    }
}

impl rand_core::TryRng for ScriptedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        match self.overrides.get(&self.drawn.len()) {
            Some(salt) if salt.len() == dest.len() => dest.copy_from_slice(salt),
            _ => rand_core::Rng::fill_bytes(&mut self.rng, dest),
        }
        self.drawn.push(dest.to_vec());
        Ok(())
    }
}

impl rand_core::TryCryptoRng for ScriptedRng {}

pub struct CliIssuer {
    signing_key: AnySigningKey,
}

impl Issuer for CliIssuer {
    type Error = EsdicawtSpecError;
    type Hasher = sha2::Sha256;
    type Signer = AnySigningKey;
    type Signature = AnySignature;

    type ProtectedClaims = NoClaims;
    type UnprotectedClaims = NoClaims;
    type PayloadClaims = Value;

    fn new(signing_key: Self::Signer) -> Self {
        Self { signing_key }
    }

    fn signer(&self) -> &Self::Signer {
        &self.signing_key
    }

    fn cwt_algorithm(&self) -> coset::iana::Algorithm {
        self.signing_key.algorithm()
    }

    fn hash_algorithm(&self) -> SdHashAlg {
        SdHashAlg::Sha256
    }
}

#[cfg(test)]
mod tests {
    //! Issuing the draft's examples with their salts must give their exact bytes
    use super::*;
    use esdicawt::spec::{decoy, sd};

    const DRAFT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../draft-ietf-spice-sd-cwt");
    const NOW: u64 = 1725244200;

    fn read(path: &str) -> String {
        std::fs::read_to_string(format!("{DRAFT}/{path}")).unwrap()
    }

    fn nonces() -> Nonces {
        parse_nonces(&format!("{}\n{}", read("examples/salt_list.csv"), read("examples/decoy_list.csv"))).unwrap()
    }

    fn issue_draft_example(extra: Vec<(Value, Value)>) -> Vec<u8> {
        let issuer = AnySigningKey::from_pem(&read("issuer_privkey.pem")).unwrap();
        let holder = AnySigningKey::from_pem(&read("holder_privkey.pem")).unwrap();
        let AnySigningKey::P256(holder) = holder else { unreachable!() };
        let cnf = KeyConfirmation::try_from(holder.verifying_key()).unwrap();
        let mut claims = vec![
            (1.into(), "https://issuer.example".into()),
            (2.into(), "https://holder.example".into()),
            (4.into(), (NOW + 86400).into()),
            (5.into(), (NOW - 300).into()),
            (6.into(), NOW.into()),
            (8.into(), ciborium::Value::serialized(&cnf).unwrap()),
        ];
        claims.extend(extra);
        let (sd_cwt, _) = issue_claims(Value::Map(claims), issuer, "https://issuer.example/cose-key3", Some(&nonces()), Some(NOW)).unwrap();
        sd_cwt
    }

    fn expected(name: &str) -> String {
        hex::encode(std::fs::read(format!("{DRAFT}/examples/{name}")).unwrap())
    }

    #[test]
    fn issuer_cwt() {
        let sd_cwt = issue_draft_example(vec![
            (500.into(), true.into()),
            (sd!(501), "ABCD-123456".into()),
            (502.into(), Value::Array(vec![sd!(1549560720), sd!(1612560720), 1674004740.into()])),
            (
                503.into(),
                Value::Map(vec![("country".into(), "us".into()), (sd!("region"), "ca".into()), (sd!("postal_code"), "94188".into())]),
            ),
        ]);
        assert_eq!(hex::encode(sd_cwt), expected("issuer_cwt.cbor"));
    }

    #[test]
    fn decoy() {
        let sd_cwt = issue_draft_example(vec![
            (98.into(), Value::Array(vec![sd!("fr"), decoy!(1)])),
            (sd!(500), true.into()),
            (decoy!(2), Value::Null),
        ]);
        assert_eq!(hex::encode(sd_cwt), expected("decoy.cbor"));
    }

    #[test]
    fn nested_issuer_cwt() {
        let inspection = |license: &str, date: u64, region: &str, postal_code: &str| {
            sd!(Value::Map(vec![
                (500.into(), true.into()),
                (sd!(501), license.into()),
                (502.into(), date.into()),
                (sd!(503), Value::Map(vec![(1.into(), "us".into()), (sd!(2), region.into()), (sd!(3), postal_code.into())]),),
            ]))
        };
        let sd_cwt = issue_draft_example(vec![(
            504.into(),
            Value::Array(vec![
                inspection("DCBA-101777", 1549560720, "co", "80302"),
                inspection("EFGH-789012", 1612560720, "nv", "89155"),
                inspection("ABCD-123456", 1674004740, "ca", "94188"),
            ]),
        )]);
        assert_eq!(hex::encode(sd_cwt), expected("nested_issuer_cwt.cbor"));
    }

    #[test]
    fn should_write_back_the_salts_used() {
        let issuer = AnySigningKey::from_pem(&read("issuer_privkey.pem")).unwrap();
        let claims = Value::Map(vec![
            (1.into(), "iss".into()),
            (2.into(), "sub".into()),
            (
                8.into(),
                ciborium::Value::serialized(&KeyConfirmation::try_from(<p256::ecdsa::SigningKey as p256::elliptic_curve::Generate>::generate_from_rng(&mut rand::rng()).verifying_key()).unwrap()).unwrap(),
            ),
            (sd!(501), "ABCD-123456".into()),
            (decoy!(7), Value::Null),
        ]);
        let (sd_cwt, used) = issue_claims(claims.clone(), issuer.clone(), "kid", None, None).unwrap();
        assert_eq!(used.len(), 2);
        assert!(used.iter().any(|(k, _)| *k == NonceKey::Decoy(7)));

        // replaying with the salts used gives the same SD-CWT
        let nonces = used.iter().map(|(k, s)| (k.clone(), s.clone().try_into().unwrap())).collect::<Nonces>();
        let (replayed, _) = issue_claims(claims, issuer, "kid", Some(&nonces), None).unwrap();
        assert_eq!(Sign1::from_bytes(&sd_cwt).unwrap().sd_claims(), Sign1::from_bytes(&replayed).unwrap().sd_claims());
    }
}
