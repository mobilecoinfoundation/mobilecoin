#!/bin/bash

# Usage:
# source ./tools/download_sigstruct.sh
#
# OR
#
# NETWORK="prod.mobilecoinww.com" source ./tools/download_sigstruct.sh

# Download sigstructs from enclave-distribution.${NETWORK}/production.json,
# and set _CSS environment variables correctly for the build.
#
# source this script in order to get those variables in your shell.
#
# Use with e.g. NETWORK="test.mobilecoin.com" or NETWORK="prod.mobilecoin.com"

NETWORK="${NETWORK:-"test.mobilecoin.com"}"
ENCLAVE_VERSION_TAG="${ENCLAVE_VERSION_TAG:-"v6.0.0"}"

CONSENSUS_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production-${ENCLAVE_VERSION_TAG}.json | grep consensus-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${CONSENSUS_SIGSTRUCT_URI}

INGEST_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production-${ENCLAVE_VERSION_TAG}.json | grep ingest-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${INGEST_SIGSTRUCT_URI}

LEDGER_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production-${ENCLAVE_VERSION_TAG}.json | grep ledger-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${LEDGER_SIGSTRUCT_URI}

VIEW_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production-${ENCLAVE_VERSION_TAG}.json | grep view-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${VIEW_SIGSTRUCT_URI}

CONSENSUS_ENCLAVE_CSS="$(pwd)/consensus-enclave.css"
INGEST_ENCLAVE_CSS="$(pwd)/ingest-enclave.css"
LEDGER_ENCLAVE_CSS="$(pwd)/ledger-enclave.css"
VIEW_ENCLAVE_CSS="$(pwd)/view-enclave.css"

export CONSENSUS_ENCLAVE_CSS INGEST_ENCLAVE_CSS LEDGER_ENCLAVE_CSS VIEW_ENCLAVE_CSS
