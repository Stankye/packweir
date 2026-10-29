#!/bin/sh
set -eu
export CARGO_HOME=/tmp/cargo-home
export CARGO_REGISTRIES_PACKWEIR_TOKEN="$PACKWEIR_READ_TOKEN"
mkdir -p "$CARGO_HOME" /tmp/project/src
cat > "$CARGO_HOME/config.toml" <<'EOF'
[registries.packweir]
index = "sparse+http://gateway:8080/r/cargo/"
credential-provider = "cargo:token"
[registry]
global-credential-providers = ["cargo:token"]
EOF
cat > /tmp/project/Cargo.toml <<'EOF'
[package]
name = "packweir-client-fixture"
version = "1.0.0"
edition = "2021"
[dependencies]
packweir-fixture = { version = "=1.0.0", registry = "packweir" }
EOF
printf 'fn main() { assert_eq!(packweir_fixture::marker(), "packweir-ok"); }\n' > /tmp/project/src/main.rs
echo 'PACKWEIR_CLIENT_VERSION_BEGIN'
cargo --version
echo 'PACKWEIR_CLIENT_VERSION_END'
cargo run --manifest-path /tmp/project/Cargo.toml --quiet
