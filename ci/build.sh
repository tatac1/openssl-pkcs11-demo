#!/bin/bash

set -euxo pipefail

# Install deps

if command -v apt-get; then
    case "$OPENSSL_VERSION" in
        '1.0')
            OPENSSL_PACKAGE_NAME='libssl1.0-dev'
            ;;
        '1.1')
            OPENSSL_PACKAGE_NAME='libssl-dev'
            ;;
    esac

    apt-get update
    apt-get install -y curl gcc pkg-config "$OPENSSL_PACKAGE_NAME"

elif command -v zypper; then
    case "$OPENSSL_VERSION" in
        '1.0')
            OPENSSL_PACKAGE_NAME='libopenssl-1_0_0-devel'
            ;;
        '1.1')
            OPENSSL_PACKAGE_NAME='libopenssl-1_1-devel'
            ;;
    esac

    zypper -n in --no-recommends curl gcc pkgconf "$OPENSSL_PACKAGE_NAME"

fi


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

cargo build


# Test

cargo test --all


# Clippy

cargo clippy --all
