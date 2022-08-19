#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around the mobilecoind drain-accounts.py to set up environment for testing.
#

set -e

usage()
{
    echo "Usage:"
    echo "${0} --src <dir> --dst <dir>"
    echo "    --src - source keys directory (keys to drain)"
    echo "    --dst - destination keys directory (keys to fund)"
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
        --src )
            src="${2}"
            shift 2
            ;;
        --dst )
            dst="${2}"
            shift 2
            ;;
        --token-id )
            token_id="${2}"
            shift 2
            ;;
        --fee )
            fee="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            usage
            ;;
    esac
done

is_set src
is_set dst
is_set token_id
is_set fee

strategies_dir=/tmp/drain-accounts/strategies

# This uses some of the same lib py files as mobilecoind tests.
mkdir -p "${strategies_dir}"
cp /test/mobilecoind/strategies/* "${strategies_dir}"

pushd "${strategies_dir}" >/dev/null || exit 1

echo "-- Install requirements"
echo ""
pip3 install -r requirements.txt

echo ""
echo "-- Set up proto files"
echo ""

python3 -m grpc_tools.protoc \
    -I"/proto/api" -I"/proto/mobilecoind" -I"/proto/consensus" \
    --python_out=. \
    --grpc_python_out=. \
    /proto/api/external.proto \
    /proto/api/blockchain.proto \
    /proto/api/quorum_set.proto \
    /proto/mobilecoind/mobilecoind_api.proto \
    /proto/consensus/consensus_common.proto

echo ""
echo "-- Run integration_test.py"
echo ""
python3 drain-accounts.py \
    --key-dir "${src}" \
    --dest-key-dir "${dst}" \
    --mobilecoind-host "mobilecoind" \
    --mobilecoind-port 3229 \
    --token-id "${token_id}" \
    --fee "${fee}"

popd >/dev/null || exit 1
