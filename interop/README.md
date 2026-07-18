# How to run this thing ?

Either run the shell script `sh run.sh` to make sure it works end to end or run commands individually ; for example
`cargo run -- issue in/issuer-priv.pem`.

# How to install ?

```
# locally
cargo install --path .

# remotely
cargo install --git https://github.com/beltram/esdicawt.git --branch interop --force
# you can also add --tag or --rev to target a specific tag/commit
```
