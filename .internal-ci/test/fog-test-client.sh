#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around fog test-client binary to set up environment for testing.
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
            token_ids="${2}"
            shift 2
            ;;
        --token-ids )
            token_ids="${2}"
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
is_set token_ids
is_set NAMESPACE

if [ -n "${CLIENT_AUTH_TOKEN_SECRET}" ]
then
    echo "Generating Client Auth Creds"
    pw=$(mc-util-grpc-token-generator --shared-secret "${CLIENT_AUTH_TOKEN_SECRET}" --username user1 | grep Password: | awk '{print $2}')
    user="user1:${pw}@"
fi

### v2.0.0 has "--token-id", v3.0.0 has "--token-ids"
# We need to figure out a way to detect what's available.

# Default to older --token-id
token_opt="--token-id ${token_ids}"

# Check for --token-ids and override the option if it exists.
if test_client --help 2>&1 | grep -E 'token-ids'
then
    token_opt="--token-ids ${token_ids}"
fi

test_client \
    --key-dir "${key_dir}" \
    --consensus "mc://node1.${NAMESPACE}.development.mobilecoin.com/" \
    --consensus "mc://node2.${NAMESPACE}.development.mobilecoin.com/" \
    --consensus "mc://node3.${NAMESPACE}.development.mobilecoin.com/" \
    ${token_opt} \
    --num-clients 6 \
    --num-transactions 32 \
    --consensus-wait 300 \
    --transfer-amount 20 \
    --fog-view "fog-view://${user}fog.${NAMESPACE}.development.mobilecoin.com:443" \
    --fog-ledger "fog-ledger://${user}fog.${NAMESPACE}.development.mobilecoin.com:443"
