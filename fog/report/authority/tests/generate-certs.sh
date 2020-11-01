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
  -key ca.key \
  -config openssl-ca.cnf \
  -extensions root_ca_ext \
  -out ${OUT_DIR}/ca.crt

# FIXME: add intermediate cert
# Generate the key for an intermediate cert
# openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr

# Tell the CA to sign the certificate
# openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -extfile openssl-ext.cnf -extensions server_cert

# Create the terminal cert
openssl genpkey -algorithm ED25519 \
  -out ${OUT_DIR}/server-ed25519.key

# Generate the certificate signing request
openssl req -new \
  -key server-ed25519.key \
  -config openssl-ed25519.cnf \
  -out ${OUT_DIR}/server-ed25519.csr

# Sign with the root cert
openssl x509 -req \
  -in server-ed25519.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -extfile openssl-ext.cnf \
  -extensions server_cert \
  -out ${OUT_DIR}/server-ed25519.crt

# Create the cert chain
cat ${OUT_DIR}/ca.crt ${OUT_DIR}/server-ed25519.crt > ${OUT_DIR}/chain.pem

popd