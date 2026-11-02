#!/bin/sh
# Builds the interop binary and registers it in the draft's interop harness
# (draft-ietf-spice-sd-cwt/interop/implementations/esdicawt), replacing the symlinks to someone else's ~/.cargo/bin.
#
# Optionally prepares the other implementations registered in the harness (python & javascript), see `--with-others`.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HARNESS="$ROOT/draft-ietf-spice-sd-cwt/interop"
DEPS="${INTEROP_DEPS_DIR:-$ROOT/target/interop-deps}"

cargo build --release --manifest-path "$ROOT/Cargo.toml" -p interop
BIN="$(cargo metadata --format-version 1 --no-deps --manifest-path "$ROOT/Cargo.toml" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')/release/interop"

for role in issue present verify target; do
  ln -sfn "$BIN" "$HARNESS/implementations/esdicawt/$role"
done
printf 'registered %s as "%s"\n' "$BIN" "$("$HARNESS/implementations/esdicawt/target")"

if [ "${1:-}" = "--with-others" ]; then
  mkdir -p "$DEPS"
  # tradeverifyd/sd-cwt (python), see SD_CWT_PYTHON in INTEROP.md
  [ -d "$DEPS/sd-cwt" ] || git clone --depth 1 https://github.com/tradeverifyd/sd-cwt.git "$DEPS/sd-cwt"
  [ -x "$DEPS/sd-cwt/.venv/bin/python" ] || python3 -m venv "$DEPS/sd-cwt/.venv"
  "$DEPS/sd-cwt/.venv/bin/python" -m pip install --quiet "$DEPS/sd-cwt" cbor2
  # tradeverifyd/sd-cwt-js (javascript), see SD_CWT_JS_DIR in INTEROP.md
  [ -d "$DEPS/sd-cwt-js" ] || git clone --depth 1 https://github.com/tradeverifyd/sd-cwt-js.git "$DEPS/sd-cwt-js"
  (cd "$DEPS/sd-cwt-js" && npm install --silent)
  echo "export SD_CWT_PYTHON=$DEPS/sd-cwt/.venv/bin/python SD_CWT_JS_DIR=$DEPS/sd-cwt-js"
fi
