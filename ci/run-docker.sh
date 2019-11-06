#!/bin/bash

set -euo pipefail

# Install deps
zypper -n in --no-recommends curl gcc pkgconf softhsm "$OPENSSL_DEVEL_PACKAGE_NAME"


# Install Rust

mkdir -p ~/.cargo/bin
curl -Lo ~/.cargo/bin/rustup 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init'
chmod +x ~/.cargo/bin/rustup
export PATH="$PATH:$(realpath ~/.cargo/bin)"

rustup self update
rustup set profile minimal

rustup install stable
rustup default stable

rustup component add clippy

export CARGO_INCREMENTAL=0


cd /src/openssl-pkcs11-demo


# Build

cargo build -p openssl-pkcs11-demo -p openssl-engine-pkcs11


# Test
#
# Ignore openssl-engine-pkcs11 when running tests because linking it for tests produces duplicate symbols. It doesn't have tests anyway.

find . -maxdepth 2 -type f -name Cargo.toml |
    grep -v openssl-engine-pkcs11 |
    while read -r file; do
        echo "-p $(basename "$(realpath "$(dirname "$file")")")"
    done |
    xargs -n99 cargo test


# Clippy

cargo clippy --all


# softhsm tests

TOKEN='Key pairs'
USER_PIN='1234'

LABEL_1='CA'
KEY_1_TYPE='ec-p256'

LABEL_2='Server'
KEY_2_TYPE='ec-p256'

LABEL_3='Client'
KEY_3_TYPE='ec-p256'

SO_PIN="so$USER_PIN"

softhsm2-util --init-token --free --label "$TOKEN" --so-pin "$SO_PIN" --pin "$USER_PIN"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" --type "$KEY_1_TYPE"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" --type "$KEY_2_TYPE"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" --type "$KEY_3_TYPE"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" load \
    --keys "pkcs11:token=$TOKEN;object=$LABEL_1" "pkcs11:token=$TOKEN;object=$LABEL_2" "pkcs11:token=$TOKEN;object=$LABEL_3"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-ca-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --subject 'CA Inc' \
    --out-file "$PWD/ca.pem"
[ -f "$PWD/ca.pem" ]

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-server-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_2?pin-value=$USER_PIN" \
    --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/server.pem"
[ -f "$PWD/server.pem" ]

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-client-cert \
    --key "pkcs11:token=$TOKEN;object=$LABEL_3?pin-value=$USER_PIN" \
    --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN;object=$LABEL_1?pin-value=$USER_PIN" \
    --out-file "$PWD/client.pem"
[ -f "$PWD/client.pem" ]
