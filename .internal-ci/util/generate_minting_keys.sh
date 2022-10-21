#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate minting keys
# See for notes on what keys do what:
# https://www.notion.so/mobilecoin/Consensus-tokens-config-and-Minting-keys-45def9fb96ff4c41ba1ec513934c45a2

set -e

usage()
{
    echo "Usage:"
    echo "${0} --token-id 8192"
    echo "    --token-id - id to generate keys for"
}

is_set()
{
    var_name="${1}"
    if [ -z "${!var_name}" ]
    then
        echo "${var_name} is not set."
        usage
        exit 1
    fi
}

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --token-id )
            token_id="${2}"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

is_set token_id

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

BASE_PATH="${BASE_PATH:-.tmp/seeds/minting}"
mkdir -p "${BASE_PATH}"

# Token governor keys
# This key pair is used to validate MintConfigTxs
if [[ ! -f "${BASE_PATH}/minter${token_id}_governor.private.pem" ]]
then
    "${location}/generate_ed25519_keys.sh" \
        --public-out "${BASE_PATH}/minter${token_id}_governor.public.pem" \
        --private-out "${BASE_PATH}/minter${token_id}_governor.private.pem"
else
    echo "minter${token_id}_governor keys already exist"
fi
sha256sum "${BASE_PATH}/minter${token_id}_governor.private.pem"
sha256sum "${BASE_PATH}/minter${token_id}_governor.public.pem"

# Token signer keys
# This key pair is used to validate MintTX
if [[ ! -f "${BASE_PATH}/token_signer.private.pem" ]]
then
    echo "Writing token${token_id}_signer keys"
    "${location}/generate_ed25519_keys.sh" \
        --public-out "${BASE_PATH}/token${token_id}_signer.public.pem" \
        --private-out "${BASE_PATH}/token${token_id}_signer.private.pem"
else
    echo "token${token_id}_signer keys already exist"
fi
sha256sum "${BASE_PATH}/token${token_id}_signer.private.pem"
sha256sum "${BASE_PATH}/token${token_id}_signer.public.pem"

# Write minting trust root private key if its defined.
if [[ -n "${MINTING_TRUST_ROOT_PRIVATE}" ]]
then
    echo "Writing minting_trust_root.private.pem"
    echo "${MINTING_TRUST_ROOT_PRIVATE}" > "${BASE_PATH}/minting_trust_root.private.pem"
    sha256sum "${BASE_PATH}/minting_trust_root.private.pem"
else
    echo "MINTING_TRUST_ROOT_PRIVATE not defined"
fi
