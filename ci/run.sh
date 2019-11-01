#!/bin/bash

set -euo pipefail

docker run --rm -v "$GITHUB_WORKSPACE:/src/openssl-pkcs11-demo" -e "OPENSSL_DEVEL_PACKAGE_NAME=$OPENSSL_DEVEL_PACKAGE_NAME" opensuse/tumbleweed "/src/openssl-pkcs11-demo/ci/run-docker.sh"
