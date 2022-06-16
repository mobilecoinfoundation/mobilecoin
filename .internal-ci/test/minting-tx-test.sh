#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around mc-consensus-mint-client binary to set up environment for testing.
#

set -e

usage()
{
    echo "Usage --key-dir <dir> --token-id <num>"
    echo "    --key-dir - source keys directory (keys to test)"
    echo "    --token-id - token id to transfer"
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
        --key-dir )
            key_dir="${2}"
            shift 2
            ;;
        --token-id )
            token_id="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

is_set key_dir
is_set token_id
is_set NAMESPACE

# These should be populated by volume in toolbox container.
token_signer_key="/minting-keys/token${token_id}_signer.private.pem"

keys=$(find "${key_dir}" -name "*.b58pub")

if [[ -z "${keys}" ]]
then
    echo "-- Error: no b58pub keys found"
    exit 1
fi

# For each b58pub in key dir run a mint-tx
for k in ${keys}
do
    echo "-- sending mint tx for account key ${k}"

    mc-consensus-mint-client generate-and-submit-mint-tx \
        --node "mc://node1.${NAMESPACE}.infradev.mobilecoin.com/" \
        --signing-key "${token_signer_key}" \
        --recipient "$(cat "${k}")" \
        --token-id "${token_id}" \
        --amount 1000000

    sleep 10
done
