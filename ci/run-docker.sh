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

TOKEN_1='CA key pair'
USER_PIN_1='1234'
SO_PIN_1="so$USER_PIN_1"
SLOT_1='0'
KEY_1_TYPE='ec-p256'

TOKEN_2='Server key pair'
USER_PIN_2='qwer'
SO_PIN_2="so$USER_PIN_2"
SLOT_2='1'
KEY_2_TYPE='ec-p256'
KEY_3_TYPE='ec-p256'

TOKEN_3='Client key pair'
USER_PIN_3='asdf'
SO_PIN_3="so$USER_PIN_3"
SLOT_3='2'

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" initialize-slot \
    --label "$TOKEN_1" --slot-id "$SLOT_1" --so-pin "$SO_PIN_1" --user-pin "$USER_PIN_1"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" initialize-slot \
    --label "$TOKEN_2" --slot-id "$SLOT_2" --so-pin "$SO_PIN_2" --user-pin "$USER_PIN_2"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" initialize-slot \
    --label "$TOKEN_3" --slot-id "$SLOT_3" --so-pin "$SO_PIN_3" --user-pin "$USER_PIN_3"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN_1?pin-value=$USER_PIN_1" --type "$KEY_1_TYPE"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN_2?pin-value=$USER_PIN_2" --type "$KEY_2_TYPE"
"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-key-pair \
    --key "pkcs11:token=$TOKEN_3?pin-value=$USER_PIN_3" --type "$KEY_3_TYPE"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" load \
    --keys "pkcs11:token=$TOKEN_1" "pkcs11:token=$TOKEN_2" "pkcs11:token=$TOKEN_3"

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-ca-cert \
    --key "pkcs11:token=$TOKEN_1?pin-value=$USER_PIN_1" \
    --subject 'CA Inc' \
    --out-file "$PWD/ca.pem"
[ -f "$PWD/ca.pem" ]

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-server-cert \
    --key "pkcs11:token=$TOKEN_2?pin-value=$USER_PIN_2" \
    --subject 'Server LLC' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN_1?pin-value=$USER_PIN_1" \
    --out-file "$PWD/server.pem"
[ -f "$PWD/server.pem" ]

"$PWD/target/debug/openssl-pkcs11-demo" --pkcs11-engine-path "$PWD/target/debug/libopenssl_engine_pkcs11.so" generate-client-cert \
    --key "pkcs11:token=$TOKEN_3?pin-value=$USER_PIN_3" \
    --subject 'Client GmbH' \
    --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN_1?pin-value=$USER_PIN_1" \
    --out-file "$PWD/client.pem"
[ -f "$PWD/client.pem" ]
