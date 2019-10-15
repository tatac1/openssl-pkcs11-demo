Proof-of-concept of using an HSM to generate and store key pairs, then using those key pairs to create a server certificate for TLS.


# Pre-requisites

- Linux
- The `openssl` library
- `softhsm`, or any other PKCS#11 library.
- `libp11` - An openssl engine that mediates between openssl and the PKCS#11 library


# How to run

1. Clean all existing softhsm slots.

    ```sh
    rm -rf ~/softhsm &&
    mkdir ~/softhsm
    ```

    where `~/softhsm` is the value of `directories.tokendir` in `/etc/softhsm2.conf`


1. Generate two key pairs.

    softhsm does not have empty uninitialized slots by default. Instead it requires slots to be initialized, after which they get a slot ID and become available. Furthermore, initializing the slots requires a label, SO PIN and user PIN. `generate-key-pair` will re-initialize the slot with new values for the label and user PIN, so the initial initialization via `softhsm2-util --init-token` just uses dummy values for those.

    For a real HSM, you would have some other way to determine which slots to use. In that case set `SLOT_1` and `SLOT_2` to the IDs of those slots.

    ```sh
    TOKEN_1='CA key pair'
    USER_PIN_1='1234'
    SO_PIN_1="so$USER_PIN_1"
    SLOT_1="$(
        softhsm2-util --init-token --free --label 'dummy' --so-pin "$SO_PIN_1" --pin 'dummy' |
            grep -Po 'The token has been initialized and is reassigned to slot\s*\K.*'
    )"
    KEY_1_TYPE='ec-p256'

    TOKEN_2='Server key pair'
    USER_PIN_2='qwer'
    SO_PIN_2="so$USER_PIN_2"
    SLOT_2="$(
        softhsm2-util --init-token --free --label 'dummy' --so-pin "$SO_PIN_2" --pin 'dummy' |
            grep -Po 'The token has been initialized and is reassigned to slot\s*\K.*'
    )"
    KEY_2_TYPE='ec-p256'

    cargo run -- generate-key-pair --label "$TOKEN_1" --slot-id "$SLOT_1" --so-pin "$SO_PIN_1" --type "$KEY_1_TYPE" --user-pin "$USER_PIN_1"

    cargo run -- generate-key-pair --label "$TOKEN_2" --slot-id "$SLOT_2" --so-pin "$SO_PIN_2" --type "$KEY_2_TYPE" --user-pin "$USER_PIN_2"
    ```

    Both invocations of `generate-key-pair` will print the public key parameters of the newly generated key - modulus and exponent for RSA, curve name and point for EC.

1. Verify the key pairs.

    ```sh
    cargo run -- load --keys "pkcs11:token=$TOKEN_1" "pkcs11:token=$TOKEN_2"
    ```

    This should print the same key parameters that `generate-key-pair` did in the previous step.

1. Generate certificates using the key pairs

    This users the first key pair to generate a CA cert (self-signed), and the second key pair to generate a server cert (signed by the CA cert).

    ```sh
    cargo run -- generate-ca-cert \
        --key "pkcs11:token=$TOKEN_1;pin-value=$USER_PIN_1" \
        --subject 'CA Inc' \
        --out-file "$PWD/ca.pem"

    cargo run -- generate-cert \
        --key "pkcs11:token=$TOKEN_2;pin-value=$USER_PIN_2" \
        --subject 'Server LLC' \
        --ca-cert "$PWD/ca.pem" --ca-key "pkcs11:token=$TOKEN_1;pin-value=$USER_PIN_1" \
        --out-file "$PWD/server.pem"
    ```

1. Start a webserver using the server cert.

    ```sh
    cargo run -- web-server --cert "$PWD/server.pem" --key "pkcs11:token=$TOKEN_2;pin-value=$USER_PIN_2"
    ```

    The web server runs on port 8443 by default. Use `--port` to use a different value.

1. Verify the cert served by the web server.

    ```sh
    < /dev/null openssl s_client -connect 127.0.0.1:8443
    ```

    This should show the cert chain and have no errors (apart from a verification error because the CA cert is untrusted).

    ```sh
    curl -kD - https://127.0.0.1:8443
    ```

    This should successfully show `curl` completing a TLS handshake and receiving `Hello, world!` from the web server.


# How to run with a TPM

TPM 2.0 hardware currently does not have a fully-functional PKCS#11 implementation. There is [`tpm2-pkcs11`](https://github.com/tpm2-software/tpm2-pkcs11) but it is not yet feature-complete, and does not work on all hardware.

Here are some notes of how to use this demo with a TPM:

- Your hardware may not work with the latest version of `tpm2-pkcs11`, so you may need a specific older version. You may also need specific older versions of [`tpm2-abrmd`,](https://github.com/tpm2-software/tpm2-abrmd) [`tpm2-tss`](https://github.com/tpm2-software/tpm2-tss) and [`tpm2-tools`.](https://github.com/tpm2-software/tpm2-tools) Consult your hardware manufacturer.

- Make sure to pass in `--pkcs11-lib-path <>` for every `openssl-pkcs11-demo` command, pointing to the `tpm2-pkcs11` library, eg `--pkcs11-lib-path '/usr/lib/pkcs11/libtpm2_pkcs11.so'`.

- Make sure to initialize the `tpm2-pkcs11` store first:

    ```sh
    tpm2_ptool init --pobj-pin=<>
    ```

    If using a custom store path (`--path <>`), make sure the path is writable by your user.

- `tpm2-pkcs11` does not support initializing tokens (its `C_InitToken` impl is stubbed out to return `CKR_FUNCTION_NOT_SUPPORTED`), so do not pass `--so-pin` to `generate-key-pair`. Then it wouldn't attempt to initialize the token itself. Of course that means you must initialize the token yourself, with `tpm2_ptool` or similar tool:

    ```sh
    tpm2_ptool addtoken --pobj-pin <> --sopin <> --userpin <> --label <> --pid <>
    ```

    `pkcs11-tool --module-path <> --list-slots` will give you the slot ID that you need for the `generate-key-pair` command. (TODO: This will become unnecessary once `generate-key-pair` learns to use the label to locate the slot.)

- `tpm2-pkcs11`'s impl of `C_GenerateKeyPair` failed for the TPM I was testing with. If this happens to you, you will have to generate the keypairs yourself instead of using `generate-key-pair`:

    ```sh
    tpm2_ptool addkey --label <> --userpin <> --algorithm <>
    ```

- `tpm2-pkcs11` only supports RSA 2048-bit keys and ECDSA P-256 keys.

- With the TPM I tested with, the web server failed to complete a TLS handshake with the `openssl` and `curl` clients while using an ECDSA P-256 server key. It worked fine with an RSA 2048-bit key.


# License

MIT
