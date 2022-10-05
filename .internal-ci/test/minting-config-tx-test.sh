#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around mc-consensus-mint-client to set up environment for testing.
#

set -e

usage()
{
    echo "Usage --token-id <num>"
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

get_block_count()
{
    curl http://mobilecoind-json:9090/ledger/local | jq -r .block_count
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
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

is_set token_id
is_set NAMESPACE

# check block height before config tx

block_count=$(get_block_count)

# These should be populated by volume in toolbox container.
governor_signer_key="/minting-keys/minter${token_id}_governor.private.pem"
token_signer_key="/minting-keys/token${token_id}_signer.public.pem"

mc-consensus-mint-client generate-and-submit-mint-config-tx \
    --node "mc://node1.${NAMESPACE}.development.mobilecoin.com/" \
    --signing-key "${governor_signer_key}" \
    --token-id "${token_id}" \
    --config "1000000000:${token_id}:${token_signer_key}" \
    --total-mint-limit 10000000000

echo "-- sleep and wait for tx/blocks to sync"

new_block_count=0
echo "-- Waiting for mint config tx to commit to the block chain"

while [[ $block_count -le $new_block_count ]]
do
    sleep 15
    new_block_count=$(get_block_count)
    echo "  Current block count: $new_block_count"
done
