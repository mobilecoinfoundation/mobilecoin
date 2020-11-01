#!/bin/bash

# Copyright (c) 2018-2020 MobileCoin Inc.

pushd "$(dirname "$0")"

OUT_DIR="$1"

# Generate the key for the CA.
openssl genrsa \
  -out ${OUT_DIR}/ca.key \
  2048

# Create the self-signed cert.
openssl req -new -x509 \
  -key ${OUT_DIR}/ca.key \
  -config openssl-ca.cnf \
  -extensions root_ca_ext \
  -out ${OUT_DIR}/ca.crt

# Create the terminal cert
openssl genpkey -algorithm ED25519 \
  -out ${OUT_DIR}/server-ed25519.key

# Generate the certificate signing request
openssl req -new \
  -key ${OUT_DIR}/server-ed25519.key \
  -config openssl-ed25519.cnf \
  -out ${OUT_DIR}/server-ed25519.csr

# Sign with the root cert
openssl x509 -req \
  -in ${OUT_DIR}/server-ed25519.csr \
  -CA ${OUT_DIR}/ca.crt \
  -CAkey ${OUT_DIR}/ca.key \
  -CAcreateserial \
  -extfile openssl-ext.cnf \
  -extensions server_cert \
  -out ${OUT_DIR}/server-ed25519.crt

# Create the cert chain
cat ${OUT_DIR}/ca.crt ${OUT_DIR}/server-ed25519.crt > ${OUT_DIR}/chain.pem

popd