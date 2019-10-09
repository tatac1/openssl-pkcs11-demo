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


# License

MIT
