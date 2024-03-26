#!/bin/bash
# Copyright (c) 2018-2023 The MobileCoin Foundation
# Monitor block sync status of mobilecoind using mobilecoind-json and consensus urls.

set -e
set -o pipefail
shopt -s inherit_errexit

get_block_info()
{
    echo "  - get ${BLOCK_INFO_URL:?}" >&2
    curl --connect-timeout 2 -fsSL -X POST -H 'Content-type: application/json' "${BLOCK_INFO_URL:?}"
}

get_mcd_ledger()
{
    echo "  - get http://localhost:9090/ledger/local" >&2
    curl --connect-timeout 2 -fsSL http://localhost:9090/ledger/local
}

get_mcd_block_details()
{
    echo "  - get http://localhost:9090/ledger/blocks/${1}/" >&2
    curl --connect-timeout 2 -fsSL "http://localhost:9090/ledger/blocks/${1}/"
}

# wait for mobilecoind-json
echo "Waiting for mobilecoind to start"
while ! get_mcd_ledger | jq -r .block_count >/dev/null 2>&1
do
    echo "- mobilecoind has not yet started, sleeping"
    sleep 10
done

# allow override of NUMBER_OF_VALIDATORS
: "${NUMBER_OF_VALIDATORS:=10}"

# wait for Ledger DB
echo "Get mobilecoind block height"
mcd_json=$(get_mcd_ledger)
echo "Get current block height"
network_block_info=$(get_block_info)

network_block_height=$(echo "${network_block_info}" | jq -r .index)
network_block_height=$((network_block_height + 1))
local_block_height=$(echo "${mcd_json}" | jq -r .block_count)

echo "Network: ${network_block_height}, Mobilecoind: ${local_block_height}"

while [[ "${local_block_height}" != "${network_block_height}" ]]
do
    sleep 10
    echo "- Waiting for blocks to download ${local_block_height} of ${network_block_height}"

    mcd_json=$(get_mcd_ledger)
    network_block_info=$(get_block_info)

    network_block_height=$(echo "${network_block_info}" | jq -r .index)
    local_block_height=$(echo "${mcd_json}" | jq -r .block_count)
    # network block height seems to be an index
    network_block_height=$((network_block_height + 1))
done

echo "Waiting for watcher db to sync - this may take a while"
signatures=0
while [[ ${signatures} -lt ${NUMBER_OF_VALIDATORS} ]]
do
    sleep 10

    # get current block
    # .block_count is height, but when we query for blocks it needs to be an index
    local_block_height=$(get_mcd_ledger | jq -r .block_count)
    local_block_height=$((local_block_height - 1))

    # get number of signatures for the current block
    signatures=$(get_mcd_block_details "${local_block_height}" | jq '.signatures | length')

    echo "- Latest block ${local_block_height} has ${signatures} of 10 signatures"
done

echo "mobilecoind sync is done"
