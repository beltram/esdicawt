# esdicawt

Rust implementation of [SD-CWT](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) currently being drafted at IETF.

Works on WASM.

```text
           +------------+
           |   Issuer   |
           |            |
           +------------+
                 |
            Issues SD-CWT
      including all Disclosures
                 |
                 v
           +------------+
           |            |
           |   Holder   |
           |            |
           +------------+
                 |
           Presents SD-KBT
    including selected Disclosures
                 |
                 v
           +-------------+
           |             |+
           |  Verifiers  ||+
           |             |||
           +-------------+||
            +-------------+|
```

## Crates

* [esdicawt](./esdicawt) the main consumer facing crate which you probably want to use. It allows crafting a SD-CWT as an `Issuer`, do a presentation (SD-KBT) as a `Holder` and verify this SD-KBT as a `Verifier`.
* [esdicawt-spec](./esdicawt-spec) just structs defined in the [draft](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) and codecs.
* [spice-oidc-cwt](./spice-oidc-cwt) OIDC standard claims for CWTs as defined in [this draft](https://beltram.github.io/rfc-spice-oidc-cwt/draft-maldant-spice-oidc-cwt.html) and feature to use it with [esdicawt](./esdicawt)
* [status-list](./status-list) Implementation (CBOR only) of Token Status List as defined in [this draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21).

Examples below are against version `0.13.2`.

## Features

There is no default feature: enable at least one cipher suite (`ed25519`, `p256`, `p384`), otherwise you must implement `Verifier::digest` yourself. Others: `pem` (load keys from PEM/DER), `status` (Token Status List), `backward` (accept tokens from older drafts), `test-vectors` (artificial time), `test-utils` (reference `Issuer`/`Holder` used below).

```toml
[dependencies]
esdicawt = { version = "0.13", features = ["ed25519", "pem"] }
```

## Overview

```text
Issuer                           Holder                         Verifier
  |                                |                                 |
  |                                +---+                             |
  |                                |   | Key Gen                     |
  |        Request SD-CWT          |<--+                             |
  |<-------------------------------|                                 |
  |                                |                                 |
  +------------------------------->|             Request Nonce       |
  |        Receive SD-CWT          +-------------------------------->|
  |                                |                                 |
  |                                |<--------------------------------+
  |                                |             Receive Nonce       |
  |                                +---+                             |
  |                                |   | Redact Claims               |
  |                                |<--+                             |
  |                                |                                 |
  |                                +---+                             |
  |                                |   | Demonstrate                 |
  |                                |<--+ Posession                   |
  |                                |                                 |
  |                                |             Present SD-CWT      |
  |                                +-------------------------------->|
  |                                |                                 |
```

## The wire format

Taken from the draft (§3 *Overview*, §14 *Examples*).

#### Given a CWT

```text
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "https://holder.example",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : {
      / cose key / 1 : {
        / kty /  1: 2,  / EC2   /
        / crv / -1: 1,  / P-256 /
        / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d9
                      2022fd0d3024b5af18c7cc61ad527a2d',
        / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5
                      503f54293d87875d1e79ce4770194343'
      }
    },
    /most_recent_inspection_passed/ 500: true,
    /inspector_license_number/ 501: "ABCD-123456",
    /inspection_dates/ 502 : [
        1549560720,   / 2019-02-07T17:32:00 /
        1612498440,   / 2021-02-04T20:14:00 /
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    /inspection_location/ 503: {
        "country": "us",            / United States /
        "region": "ca",             / California /
        "postal_code": "94188"
    }
}
```

Pass/fail, the most recent date and the country stay always visible; the license number, two dates, `region` and `postal_code` get redacted. In Rust, claims to redact are tagged with `sd!` in `Select`:

```rust,ignore
use ciborium::{Value, cbor};
use esdicawt::spec::{Select, sd};

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
struct Inspection {
    passed: bool,
    license: String,
    dates: Vec<u64>,
}

impl Select for Inspection {
    fn select(self) -> Result<Value, ciborium::value::Error> {
        Ok(cbor!({
            "passed" => self.passed,
            "license" => self.license,
            "dates" => self.dates,
            sd!("region") => "ca",
            sd!("postal_code") => "94188",
        })
        .unwrap())
    }
}
```

`SelectExt::select_all` / `select_root` / `select_none` cover redacting everything, top-level labels only, or nothing; `Redact::redact` redacts in place.

#### An issuer generates a SD-CWT

```text
/ cose-sign1 / 18([  / issuer SD-CWT /
  / CWT protected / << {
    / alg /    1  : -35, / ES384 /
    / kid /    4  : 'https://issuer.example/cose-key3',
    / typ /    16 : 293, # application/sd-cwt
    / sd_alg / 170 : -16  / SHA256 /
  } >>,
  / CWT unprotected / {
    / sd_claims / 17 : [ / these are all the disclosures /
        <<[
            /salt/   h'bae611067bb823486797da1ebbb52f83',
            /value/  "ABCD-123456",
            /claim/  501   / inspector_license_number /
        ]>>,
        <<[
            /salt/   h'8de86a012b3043ae6e4457b9e1aaab80',
            /value/  1549560720   / inspected 7-Feb-2019 /
        ]>>,
        <<[
            /salt/   h'7af7084b50badeb57d49ea34627c7a52',
            /value/  1612560720   / inspected 4-Feb-2021 /
        ]>>,
        <<[
            /salt/   h'ec615c3035d5a4ff2f5ae29ded683c8e',
            /value/  "ca",
            /claim/  "region"   / region=California /
        ]>>,
        <<[
            /salt/   h'37c23d4ec4db0806601e6b6dc6670df9',
            /value/  "94188",
            /claim/  "postal_code"
        ]>>,
    ]
  },
  / CWT payload / << {
    / iss / 1   : "https://issuer.example",
    / sub / 2   : "https://holder.example",
    / exp / 4   : 1725330600,  /2024-09-03T02:30:00+00:00Z/
    / nbf / 5   : 1725243900,  /2024-09-02T02:25:00+00:00Z/
    / iat / 6   : 1725244200,  /2024-09-02T02:30:00+00:00Z/
    / cnf / 8   : {
      / cose key / 1 : {
        / kty /  1: 2,  / EC2   /
        / crv / -1: 1,  / P-256 /
        / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d9
                      2022fd0d3024b5af18c7cc61ad527a2d',
        / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5
                      503f54293d87875d1e79ce4770194343'
      }
    },
    /most_recent_inspection_passed/ 500: true,
    /inspection_dates/ 502 : [
        / redacted inspection date 7-Feb-2019 /
        60(h'1b7fc8ecf4b1290712497d226c04b503
             b4aa126c603c83b75d2679c3c613f3fd'),
        / redacted inspection date 4-Feb-2021 /
        60(h'64afccd3ad52da405329ad935de1fb36
             814ec48fdfd79e3a108ef858e291e146'),
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    / inspection_location / 503 : {
        "country" : "us",            / United States /
        / redacted_claim_keys / simple(59) : [
            / redacted region /
            h'0d4b8c6123f287a1698ff2db15764564
              a976fb742606e8fd00e2140656ba0df3'
            / redacted postal_code /
            h'c0b7747f960fc2e201c4d47c64fee141
              b78e3ab768ce941863dc8914e8f5815f'
      ]
    },
    / redacted_claim_keys / simple(59) : [
        / redacted inspector_license_number /
        h'af375dc3fba1d082448642c00be7b2f7
          bb05c9d8fb61cfc230ddfdfb4616a693'
    ]
  } >>,
  / CWT signature / h'12bdb0136ed93db0e3400660d5aee1ba
                      68ff24e743d613eea55d3bedff167ae4
                      d3c9c328ebfdc1793a178e754ce11432
                      f2e69a92eee6953d38d5a58830ece550
                      21951a83e4e30365828bb7918ceb187a
                      21da18c071ce2461ef642a9e7959299e'
])
```

A disclosure is a `bstr`-wrapped `[salt, value]` (array element) or `[salt, value, claim-key]` (map key). Map-key digests go in a `redacted_claim_keys` array under CBOR simple value `59`, at the same level as the original claim; array-element digests replace the element, wrapped in tag `60`. Both hash the whole `bstr` with the algorithm in `sd_alg`. An empty `sd_claims` is invalid, so it is omitted when nothing is redacted.

```rust,ignore
use esdicawt::{Issuer, IssuerParams, StatusParams, spec::CwtAny};
use esdicawt::test_utils::Ed25519Issuer; // feature = "test-utils"

let issuer = Ed25519Issuer::<Inspection>::new(issuer_signing_key);

let params = IssuerParams {
    protected_claims: None,
    unprotected_claims: None,
    payload: Some(Inspection {
        passed: true,
        license: "ABCD-123456".into(),
        dates: vec![1549560720, 1612498440, 1674004740],
    }),
    issuer: "https://issuer.example",
    subject: Some("https://holder.example"),
    audience: None,
    cti: None,
    cnonce: None,
    expiry: None,
    with_not_before: true,
    with_issued_at: true,
    leeway: core::time::Duration::from_secs(1),
    key_location: "https://issuer.example/key.cwk",
    holder_confirmation_key: (&holder_verifying_key).try_into().unwrap(),
    // `status` only with feature = "status", `artificial_time` only with feature = "test-vectors"
    status: StatusParams {
        status_list_bit_index: 0,
        uri: "https://example.com/statuslists/1".parse().unwrap(),
    },
};

let sd_cwt = issuer.issue_cwt(&mut rand::thread_rng(), params)?; // or `issue_raw_cwt` for bytes
let sd_cwt_raw = sd_cwt.to_cbor_bytes()?;
```

#### A Holder then presents a SD-KBT

The Holder picks the disclosures to present — here `region` and `dates`:

```text
    / sd_claims / 17 : [ / these are the disclosures /
        <<[
            /salt/   h'8de86a012b3043ae6e4457b9e1aaab80',
            /value/  1549560720   / inspected 7-Feb-2019 /
        ]>>,
        <<[
            /salt/   h'ec615c3035d5a4ff2f5ae29ded683c8e',
            /value/  "ca",
            /claim/  "region"   / region=California /
        ]>>,
    ]
```

The issued SD-CWT, carrying those disclosures in its unprotected header, goes in the `kcwt` (RFC 9528) protected header of the SD-KBT:

```text
/ cose-sign1 / 18( / sd_kbt / [
  / KBT protected / << {
    / alg /    1:  -7, / ES256 /
    / kcwt /  13:  ...
           /  *** SD-CWT from Issuer goes here      /
           /  with Holder's choice of disclosures   /
           /  in the SD-CWT unprotected header  *** /,
    / end of issuer SD-CWT /
    / typ /   16:  294   # application/kb+cwt,
  } >>,     / end of KBT protected header /
  / KBT unprotected / {},
  / KBT payload / << {
    / aud    /  3    : "https://verifier.example/app",
    / iat    /  6    : 1725244237, / 2024-09-02T02:30:37+00:00Z /
    / cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803'
  } >>,      / end of KBT payload /
  / KBT signature / h'ca38c411693201ceb418ab75217745cc
                      f1d52f76c934ce2910a9f4ccc4293711
                      f9ee18347b51f6f815d89b77d407e494
                      5551118df8f9b662e5250fb1c5f070c8'
])   / end of kbt /
```

That unprotected header is covered by the KBT signature, so the Verifier knows the Holder sent that list.

```rust,ignore
use esdicawt::{CborPath, Holder, HolderParams, HolderValidationParams, Presentation, TokenQuery, spec::CwtAny};
use esdicawt::test_utils::Ed25519Holder; // feature = "test-utils"

let holder = Ed25519Holder::<Inspection, NoClaims>::new(holder_signing_key);
let sd_cwt = holder.verify_sd_cwt(&sd_cwt_raw, HolderValidationParams::default(), &cks)?;

let presentation = Presentation::Path(Box::new(|path: &[CborPath]| {
    matches!(path, [CborPath::Str(label)] if label == "region" || label == "dates")
}));

let sd_kbt = holder.new_presentation(sd_cwt, HolderParams {
    presentation,
    audience: "https://verifier.example/app",
    cnonce: None,
    expiry: None,
    with_not_before: false,
    time_verification: Default::default(),
    leeway: Default::default(),
    extra_kbt_protected: None,
    extra_kbt_unprotected: None,
    extra_kbt_payload: None,
    // `artificial_time` only with feature = "test-vectors"
})?;
let sd_kbt_raw = sd_kbt.to_cbor_bytes()?;

assert_eq!(sd_kbt.query(vec!["region".into()].into())?, Some(cbor!("ca").unwrap()));
assert_eq!(sd_kbt.query(vec!["postal_code".into()].into())?, None);
```

`Presentation` variants: `Full` (default), `None`, `Path` (by CBOR path, above), `Custom` (filter the `SaltedArray`).

#### Verifier

```rust,ignore
use esdicawt::{TokenQuery, Verifier, VerifierParams};

let verified = verifier.verify_sd_kbt(
    &sd_kbt_raw,
    &VerifierParams {
        expected_kbt_audience: &["https://verifier.example/app"],
        ..Default::default()
    },
    Some(&holder_verifying_key), // optional: proves possession of the Holder key
    &cks,                        // issuer key set
)?;

assert_eq!(verified.claimset.as_ref().unwrap().license, "ABCD-123456");
assert_eq!(verified.query(vec!["passed".into()].into())?, Some(cbor!(true).unwrap()));
assert_eq!(verified.query(vec!["dates".into(), 1usize.into()].into())?, Some(cbor!(1612498440).unwrap()));
```

Checks both signatures, the digests against the disclosures, and the time claims, then rebuilds the claimset. Also available: `shallow_verify_sd_kbt` (signatures and time claims only, skips the expensive claimset rebuild, takes `ShallowVerifierParams`), `verify_sd_kbt_batch`, and `verify_sd_kbt_with_status` (`VerifierWithStatus`, feature `status`, async).

`expected_kbt_audience` is a list; the SD-KBT `aud` must equal one of them, and an empty list accepts any.

## Reading claims

`TokenQuery` is implemented on `SdCwtIssued`, `SdCwtVerified`, `KbtCwt` and `KbtCwtVerified`, so claims read the same way at every stage:

```rust,ignore
sd_cwt.query(vec!["region".into()].into())?;                    // text label
sd_cwt.query(vec![501i64.into()].into())?;                      // integer label
sd_cwt.query(vec!["dates".into(), 0usize.into()].into())?;      // array index

sd_cwt.sub()?; sd_cwt.iss()?; sd_cwt.aud()?;                    // `SdCwtRead`
sd_cwt.exp()?; sd_cwt.nbf()?; sd_cwt.iat()?;
```

On the Issuer/Holder side a query resolves redacted claims through the disclosures; on `KbtCwtVerified` it resolves against the claimset that survived verification, so an undisclosed claim reads as `None`.

`CwtAny::from_cbor_bytes` decodes without verifying, e.g. `KbtCwt::<Inspection, sha2::Sha256>::from_cbor_bytes(&bytes)`. `ClaimSetExt::claimset_unchecked` builds a claimset without checking the signature — at your own risk.

## Decoys

`decoy!(n)` asks the Issuer for a decoy digest, as an array element or a map label whose value is `null`; `n` must be unique per decoy. They widen the verifier's search space and are never presented, whatever the `Presentation`, since presenting them would reveal which digests are decoys.

## Implementing the roles

No production `Issuer`/`Holder`/`Verifier` ships with the crate — you implement the traits for your key types. Mostly associated types:

```rust,ignore
use esdicawt::{Verifier, spec::{CustomClaims, NoClaims, Select}};

pub struct Ed25519Verifier<T: Select, U: CustomClaims = NoClaims> {
    _marker: core::marker::PhantomData<(T, U)>,
}

impl<T: Select, U: CustomClaims> Verifier for Ed25519Verifier<T, U> {
    type Error = std::convert::Infallible;
    type HolderSignature = ed25519_dalek::Signature;
    type HolderVerifier = ed25519_dalek::VerifyingKey;
    type IssuerProtectedClaims = NoClaims;
    type IssuerUnprotectedClaims = NoClaims;
    type IssuerPayloadClaims = T;
    type KbtPayloadClaims = U;
    type KbtProtectedClaims = NoClaims;
    type KbtUnprotectedClaims = NoClaims;
}
```

That is the whole impl — `digest` is defaulted when a cipher-suite feature is on. `Issuer` also needs `new`, `signer`, `cwt_algorithm`, `hash_algorithm`; `Holder` needs `new`, `signer`, `verifier`, `cwt_algorithm`. Ed25519 and P-256 impls are behind `feature = "test-utils"` and in `esdicawt/tests/crypto.rs`, the best thing to copy. Keys for the Holder and Verifier go in a COSE key set: `CoseKeySet::builder().with(&issuer_verifying_key)?.build()`.

## Draft conformance

`draft-ietf-spice-sd-cwt` is a submodule of the working draft; the examples above come from its `examples/*.edn`. The wire format moves between revisions, so pin what you build against.

* Headers: `alg` 1, `kid` 4, `kcwt` 13, `typ` 16, `sd_claims` 17, `sd_alg` 170.
* `typ`: 293 `application/sd-cwt`, 294 `application/kb+cwt`.
* Tags: 58 *To Be Redacted*, 60 *Redacted Claim Element*, 62 *To Be Decoy*; `redacted_claim_keys` is simple value 59.
* Salts are 128-bit.

Older revisions differ on the wire (e.g. digests were not taken over the `bstr`-wrapped disclosure, and `kcwt` was itself wrapped in a `bstr`); `feature = "backward"` accepts such tokens. Draft test vectors live in `esdicawt-test-vector`, byte-exact snapshots in `esdicawt/src/snapshots/`.

## Building

```console
cargo build
cargo test                          # CI also runs: cargo test --features backward
cargo fmt --all -- --check
cargo clippy --tests -- -D warnings
cargo hack check --feature-powerset --no-dev-deps   # each feature alone
```

WASM: `wasm-pack test --headless --chrome ./esdicawt`.
