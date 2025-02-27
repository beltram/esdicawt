# esdicawt

Rust implementation of [SD-CWT](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) currently
being drafted at IETF.

Works on WASM (or at least is supposed to).

🚧🚧🚧 Work in progress... !!! Not fully spec compliant, not interoperable yet ! 🚧🚧🚧

```
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

This project contains the following crates:
* [esdicawt](./esdicawt) the main consumer facing crate which you probably want to use. It allows crafting a SD-CWT as an `Issuer`, do a presentation (SD-KBT) as a `Holder` and verify this SD-KBT as a `Verifier`.
* [esdicawt-spec](./esdicawt-spec) just structs defined in the [draft](https://ietf-wg-spice.github.io/draft-ietf-spice-sd-cwt/draft-ietf-spice-sd-cwt.html) and codecs.
* [cose-key](./cose-key) helpers to convert public keys from rustcrypto crates into a [CoseKey](https://datatracker.ietf.org/doc/html/rfc8152)
* [cose-key-confirmation](./cose-key-confirmation) Proof of Possession for CWTs as defined in [RFC 8747](https://www.rfc-editor.org/rfc/rfc8747)
* [cose-key-set](./cose-key-set) Similar to JWKS (Json Web KeySet) for key directories
* [cose-key-thumbprint](./cose-key-thumbprint) Generates a digest of a CoseKey as defined in [RFC 9679](https://datatracker.ietf.org/doc/html/rfc9679)
* [spice-oidc-cwt](./spice-oidc-cwt) OIDC standard claims for CWTs as defined in [this draft](https://beltram.github.io/rfc-spice-oidc-cwt/draft-maldant-spice-oidc-cwt.html) and feature to use it with [esdicawt](./esdicawt)
