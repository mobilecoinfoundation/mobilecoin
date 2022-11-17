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

# Whether we pass a json file to the mint client or use command line arguments instead
json_flag="0"

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
        --json )
            json_flag="1"
            shift 1
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
echo "Current block count: $block_count"
echo "JSON flag: $json_flag"

# These should be populated by volume in toolbox container.
governor_signer_key="/minting-keys/token_${token_id}_governor_1.private.pem"
token_signer_key="/minting-keys/token_${token_id}_signer_1.public.pem"

if [ "$json_flag" == "0" ]; then
    mc-consensus-mint-client generate-and-submit-mint-config-tx \
        --node "mc://node1.${NAMESPACE}.development.mobilecoin.com/" \
        --signing-key "${governor_signer_key}" \
        --token-id "${token_id}" \
        --config "1000000000:1:${token_signer_key}" \
        --total-mint-limit 10000000000
else
    location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
    mint_config_file="${location}/minting-config-tx.json"
    if [[ ! -f "$mint_config_file" ]]; then
        echo "$mint_config_file does not exist"
        exit 1
    fi

    token_signer_key_contents=$(cat ${token_signer_key})

    json=$(cat "${mint_config_file}")
    json=$(echo "${json}" | jq ".token_id = $token_id")
    json=$(echo "${json}" | jq ".configs[0].minters.pub_key = \"$token_signer_key_contents\"")
    echo $json

    json_file="/tmp/mint-config.${token_id}.json"
    echo $json > ${json_file}

    mc-consensus-mint-client generate-and-submit-mint-config-tx \
        --node "mc://node1.${NAMESPACE}.development.mobilecoin.com/" \
        --signing-key "${governor_signer_key}" \
        --mint-config-tx-file "${json_file}"
fi

new_block_count=0
echo "-- Waiting for mint config tx to commit to the block chain"

while [[ $block_count -ge $new_block_count ]]
do
    echo "Sleeping"
    sleep 15
    new_block_count=$(get_block_count)
    echo "  Current block count: $new_block_count"
done
