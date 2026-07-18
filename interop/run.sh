#cargo install --path . --profile dev
cat in/input.cbor |
cargo run -- issue in/issuer-priv.pem |
cargo run -- present in/holder-priv.pem --issuer in/issuer-pub.pem --issuer-key ignore |
cargo run -- verify --issuer in/issuer-pub.pem --issuer-key ignore
