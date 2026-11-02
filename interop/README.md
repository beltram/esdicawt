# interop

The `issue`, `present`, `verify` and `target` programs of
[INTEROP.md](../draft-ietf-spice-sd-cwt/interop/INTEROP.md), so that esdicawt takes part in the interop harness of
the draft (`draft-ietf-spice-sd-cwt/interop`).

It is a single binary, called either through symlinks named after each program (what the harness does) or with the
program as first argument: `interop present holder_priv.pem --issuer issuer_pub.pem < issued.cbor`.

Not a default member of the workspace: other members enable the `status` feature of esdicawt, which would be unified
with this crate's. Build it with `cargo build -p interop`.

## Run the interop tests

```sh
# builds the binary and points draft-ietf-spice-sd-cwt/interop/implementations/esdicawt/* at it
interop/setup.sh
# optionally, also clones and installs the python and javascript implementations under target/interop-deps,
# then prints the SD_CWT_PYTHON / SD_CWT_JS_DIR variables to export
interop/setup.sh --with-others

# every test case, for every Issuer x Holder x Verifier available (needs cbor2)
interop/run_matrix.py
# or only the harness's AEAD test case
python3 draft-ietf-spice-sd-cwt/interop/run_aead.py --impl esdicawt
```

`run_matrix.py` writes `results.json` and the logs of every program run to `target/interop-results/{timestamp}/`.
Its test cases:

| Case | What is checked |
|---|---|
| `draft_kbt`, `draft_nested_kbt` | each Verifier verifies the draft's presentations and outputs the disclosed claims |
| `negative` | each Verifier rejects a wrong `--audience`, an expired SD-CWT (`--time`) and a tampered signature |
| `draft_present` | each Holder presents the draft's `issued.cbor` with `disclosure_list.cbor`, each Verifier verifies it |
| `draft_issue` | each Issuer issues the draft's claims set with its salts (`--nonces`), the result must equal `issuer_cwt.cbor`; then Holder x Verifier |
| `shipping_manifest4` | each Issuer issues the case's claims set (the case has no Holder private key, so no presentation) |
| `aead_first_disclosure` | the harness's `run_aead.py`, for each Holder x Verifier |

`cargo test -p interop` checks the issuance of the draft's `issuer_cwt.cbor`, `decoy.cbor` and `nested_issuer_cwt.cbor`
byte for byte, and the verification of a SD-KBT carrying AEAD encrypted disclosures.

## Deviations from INTEROP.md

- without `--time`, time claims are not verified at all: the draft's examples expired in 2024, and the harness's
  `run_aead.py` gives no `--time`
- Ed25519, P-256 and P-384 keys only, SHA-256 only
- AEAD encrypted disclosures (`sd_aead_encrypted_claims`, 171) are not implemented: `present --encrypt_list` and
  `verify --aead-key` (when the SD-KBT has encrypted disclosures) exit with code 2. Without a key, `verify` leaves them
  undisclosed
- `--issuer-key ignore` and `fetch` exit with code 2: esdicawt always verifies the Issuer signature and does not fetch
  keys. `cache` loads the file named after the last path segment of the `kid` URL from the current directory
- `issue` takes an extra `--kid` (defaults to the draft's `https://issuer.example/cose-key3`), and requires `iss`,
  `sub` and `cnf` in the claims set. `iat` and `nbf` are honored when `nbf <= iat`
- `verify` requires an expected subject, so it takes the one of the SD-CWT
