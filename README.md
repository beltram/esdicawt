# esdicawt

Rust implementation of [SD-CWT](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) currently being drafted at IETF.

Works on WASM (or at least is supposed to).

🚧🚧🚧 Work in progress... !!! Not fully spec compliant, not interoperable yet ! 🚧🚧🚧

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
           Presents SD-CWT
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

This project contains the following crates:
* [esdicawt](./esdicawt) the main consumer facing crate which you probably want to use. It allows crafting a SD-CWT as an `Issuer`, do a presentation (SD-KBT) as a `Holder` and verify this SD-KBT as a `Verifier`.
* [esdicawt-spec](./esdicawt-spec) just structs defined in the [draft](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) and codecs.
* [cose-key](./cose-key) helpers to convert public keys from rustcrypto crates into a [CoseKey](https://datatracker.ietf.org/doc/html/rfc8152)
* [cose-key-confirmation](./cose-key-confirmation) Proof of Possession for CWTs as defined in [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747)
* [cose-key-set](./cose-key-set) Similar to JWKS (Json Web KeySet) for key directories
* [cose-key-thumbprint](./cose-key-thumbprint) Generates a digest of a CoseKey as defined in [RFC 9679](https://datatracker.ietf.org/doc/html/rfc9679)
* [spice-oidc-cwt](./spice-oidc-cwt) OIDC standard claims for CWTs as defined in [this draft](https://beltram.github.io/rfc-spice-oidc-cwt/draft-maldant-spice-oidc-cwt.html) and feature to use it with [esdicawt](./esdicawt)

## Overview

#### Issuance & Presentation flow

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

#### Given a CWT

```text
{
    / iss / 1  : "https://issuer.example",
    / sub / 2  : "https://device.example",
    / exp / 4  : 1725330600, /2024-09-02T19:30:00Z/
    / nbf / 5  : 1725243840, /2024-09-01T19:25:00Z/
    / iat / 6  : 1725244200, /2024-09-01T19:30:00Z/
    / cnf / 8  : {
      / cose key / 1 : {
        / kty /  1: 2,  / EC2   /
        / crv / -1: 1,  / P-256 /
        / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
        / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
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
        "country": "us", / United States /
        "region": "ca", / California /
        "postal_code": "94188"
    }
}
```

```rust,ignore
pub struct CarInspection {
    pub most_recent_inspection_passed: bool,
    pub inspector_license_number: String,
    pub inspection_dates: Vec<u64>,
    pub inspection_location: Vec<spice_oidc_cwt::OidcAddressClaim>,
}
```

#### An issuer generates a SD-CWT

```text
/ cose-sign1 / 18([  / issuer SD-CWT /
  / CWT protected / << {
    / alg /    1  : -35, / ES384 /
    / typ /    16 : "application/sd+cwt",
    / kid /    4  : 'https://issuer.example/cwt-key3',
    / sd_alg / 18 : -16  / SHA256 /
  } >>,
  / CWT unprotected / {
    / sd_claims / 17 : [ / these are all the disclosures /
        <<[ /salt/   h'2008c50a62d9b59813318abd06df8a89', /value/  "ABCD-123456", /claim/  501,   / inspector_license_number / ]>>,
        <<[ /salt/   h'7afa9ed5103ecca7357c628f549a3581', /value/  1549560720   / inspected 7-Feb-2019 / ]>>,
        <<[ /salt/   h'033b375a7bc327497148458b3447cc46', /value/  1612560720   / inspected 4-Feb-2021 / ]>>,
        <<[ /salt/   h'ef016cb1438d09d8b48ceee1709e2072', /value/  "ca", /claim/  "region"   / region=California / ]>>,
        <<[ /salt/   h'92753ef207fed9a767d75aec16ac0d18', /value/  "94188", /claim/  "postal_code" ]>>,
    ]
  }
  / CWT payload / << {
    / iss / 1   : "https://issuer.example",
    / sub / 2   : "https://device.example",
    / exp / 4   : 1725330600,  /2024-09-03T02:30:00+00:00Z/
    / nbf / 5   : 1725243900,  /2024-09-02T02:25:00+00:00Z/
    / iat / 6   : 1725244200,  /2024-09-02T02:30:00+00:00Z/
    / cnf / 8   : {
      / cose key / 1 : {
        / kty /  1: 2,  / EC2   /
        / crv / -1: 1,  / P-256 /
        / x /   -2: h'8554eb275dcd6fbd1c7ac641aa2c90d92022fd0d3024b5af18c7cc61ad527a2d',
        / y /   -3: h'4dc7ae2c677e96d0cc82597655ce92d5503f54293d87875d1e79ce4770194343'
      }
    },
    /most_recent_inspection_passed/ 500: true,
    / redacted_claim_keys / 59(0) : [
        / redacted inspector_license_number / h'7d493be2eb59b6b9bbb81da46a72fc25074481a7bfd8b2b2d8ce5a0d31ef2108'
    ],
    /inspection_dates/ 502 : [
        / redacted inspection date 7-Feb-2019 / 60(h'6db57c149ae619140db846203f67e3edf42f2cd8ac71feaab4684296077f1dc1'),
        / redacted inspection date 4-Feb-2021 / 60(h'e08fe0d7fcdaaa7cc6d0640405d2d9527f01af8d0cd9da190ea7f85197b0b0f0'),
        1674004740,   / 2023-01-17T17:19:00 /
    ],
    / inspection_location / 503 : {
        "country" : "us", / United States /
        / redacted_claim_keys / 59(0) : [
            / redacted region / h'da8fb0da7f25d2e431e29acc3996a41817c39b7b0fc0d6c0603df29a3d548a0b'
            / redacted postal_code / h'a4c4f26f027f12f40f77e3800fff0cf0d6a9c0a282c3c0f6a2ba4a08c293bc05'
      ]
    }
  } >>,
  / CWT signature / h'14d9566069bd96fd0d20ce37ad9b7bfb5d0e8e36dc665ffffa80b3dcbf76f66aa28adff482c3ffa660b30c4115fba350e30108fe2436388a9bd280893570e4163935146abee5e11248ce71c8b7f7e634cdb8feeccfb6439e2131ba03c1f0f65e'
])
```



#### A Holder then presents a SD-KBT

Holder decides to disclose `region`, `inspector_license_number` and `inspection_dates` from the previous disclosures:

```text
/ sd_claims / 17 : [ / these are the disclosures /
    <<[ /salt/   h'2008c50a62d9b59813318abd06df8a89', /value/  "ABCD-123456" /claim/  501, / inspector_license_number / ]>>,
    <<[ /salt/   h'7afa9ed5103ecca7357c628f549a3581', /value/  1549560720 / inspected 7-Feb-2019 / ]>>,
    <<[ /salt/   h'ef016cb1438d09d8b48ceee1709e2072', /value/  "ca" /claim/  "region", / region=California / ]>>,
]
```

He does the presentation of this in a `SD-KBT` with only the 3 previous disclosures kept:

```text
/ cose-sign1 / 18( / sd_kbt / [
  / KBT protected / << {
    / alg /    1:  -7, / ES256 /
    / typ /   16:  "application/kb+cwt",
    / kcwt /  13:  ...
           /  *** SD-CWT from Issuer goes here with Holder's choice of disclosures in the SD-CWT unprotected header  *** /
     / end of issuer SD-CWT /
  } >>,     / end of KBT protected header /
  / KBT unprotected / {},
  / KBT payload / << {
    / cnonce / 39    : h'8c0f5f523b95bea44a9a48c649240803',
    / aud    /  3    : "https://verifier.example/app",
    / iat    /  6    : 1725244237, / 2024-09-02T02:30:37+00:00Z /
  } >>,      / end of KBT payload /
  / KBT signature / h'db30ece366b9493155d2d80305c0e54b4457dda88cb6fc2de7e5756780590055147af721344c4e5b59c03c7b1eec8621c2a0647fb033d2e70a48063d37a96ab7'
])   / end of kbt /
```

#### Verifier

Verifies the SD-KBT and reads the claims.
