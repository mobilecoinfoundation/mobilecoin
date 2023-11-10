#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# check-env-status.sh - loop and wait for expected block height and active ingress endpoints.

usage()
{
    echo "Usage: $0 --minimum-block "
    echo "    --minimum - block height for environment to be considered ready."
}

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --minimum-block )
            minimum_block="${2}"
            shift 2
            ;;
        --namespace )
            namespace="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

# Check to see if these vars are set
: "${minimum_block:?}"
: "${namespace:?}"

check()
{
    curl --max-time 5 --retry 2 -sSLf -X POST "${1}"
}

check_timeout()
{
    if [[ ${1} -gt 300 ]]
    then
        echo "Failed to come up in 10m"
        exit 1
    fi
    sleep 2
}

# check consensus nodes.
for n in 1 2 3
do
    counter=0
    block_height=0
    echo "Waiting for consensus node${n}.${namespace}.development.mobilecoin.com"
    while [[ ${block_height} -lt ${minimum_block} ]]
    do
        block_info=$(check https://node${n}.${namespace}.development.mobilecoin.com/gw/consensus_common.BlockchainAPI/GetLastBlockInfo)
        block_height=$(jq -r -n --argjson data "${block_info}" '$data.index')
        echo "  current: ${block_height} minimum: ${minimum_block}"

        check_timeout $(( counter++ ))
    done
done

# check report has a value...
for r in fog fog-b fog-report-b
do
    counter=0
    pubkey=""
    while [[ -z "${pubkey}" ]]
    do
        echo "Waiting for fog-report fog://${r}.${namespace}.development.mobilecoin.com"
        if report_info=$(/usr/local/bin/fog-report-cli -n -v -u "fog://${r}.${namespace}.development.mobilecoin.com")
        then
            pubkey=$(jq -r -n --argjson data "${report_info}" '$data.pubkey')
        fi
        check_timeout $(( counter++ ))
    done
        echo "  ${pubkey}"
done

# check ledger
for l in fog fog-b
do
    counter=0
    block_height=0
    echo "Waiting for fog-ledger fog://${l}.${namespace}.development.mobilecoin.com"
    while [[ ${block_height} -lt ${minimum_block} ]]
    do
        block_info=$(check https://${l}.${namespace}.development.mobilecoin.com/gw/fog_ledger.FogBlockAPI/GetBlocks)
        block_height=$(jq -r -n --argjson data "${block_info}" '$data.numBlocks')
        echo "  current: ${block_height} minimum: ${minimum_block}"

        check_timeout $(( counter++ ))
    done
done

# no way to check view right now :(
