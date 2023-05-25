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

if [ -z ${NETWORK+x} ]; then
    NETWORK="test.mobilecoin.com"
fi

CONSENSUS_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production.json | grep consensus-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${CONSENSUS_SIGSTRUCT_URI}
INGEST_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production.json | grep ingest-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${INGEST_SIGSTRUCT_URI}
LEDGER_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production.json | grep ledger-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${LEDGER_SIGSTRUCT_URI}
VIEW_SIGSTRUCT_URI=$(curl -s https://enclave-distribution.${NETWORK}/production.json | grep view-enclave.css | awk '{print $2}' | tr -d \" | tr -d ,)
curl -O https://enclave-distribution.${NETWORK}/${VIEW_SIGSTRUCT_URI}
export CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css
export INGEST_ENCLAVE_CSS=$(pwd)/ingest-enclave.css
export LEDGER_ENCLAVE_CSS=$(pwd)/ledger-enclave.css
export VIEW_ENCLAVE_CSS=$(pwd)/view-enclave.css
