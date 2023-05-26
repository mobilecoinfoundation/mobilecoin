#!/bin/bash
# Copyright (c) 2018-2023 The MobileCoin Foundation
# Monitor block sync status of mobilecoind using mobilecoind-json and consensus urls.

set -e
set -o pipefail
shopt -s inherit_errexit

echo "Checking block height - wait for mobilecoind to start"
sleep 15

get_block_info()
{
    curl --connect-timeout 2 -sSL -X POST -H 'Content-type: application/json' "${BLOCK_INFO_URL:?}" 2>/dev/null
}

get_mcd_ledger()
{
    curl --connect-timeout 2 -sSL http://localhost:9090/ledger/local 2>/dev/null
}

# wait for blocks
mcd_json=$(get_mcd_ledger)
network_block_info=$(get_block_info)

network_block_height=$(echo "${network_block_info}" | jq -r .index)
local_block_height=$(echo "${mcd_json}" | jq -r .block_count)

while [[ "${local_block_height}" != "${network_block_height}" ]]
do
    echo "- Waiting for blocks to download ${local_block_height} of ${network_block_height}"

    mcd_json=$(get_mcd_ledger)
    network_block_info=$(get_block_info)

    network_block_height=$(echo "${network_block_info}" | jq -r .index)
    local_block_height=$(echo "${mcd_json}" | jq -r .block_count)
    # network block height seems to be an index
    network_block_height=$((network_block_height + 1))

    sleep 10
done

echo "mobilecoind sync is done"
