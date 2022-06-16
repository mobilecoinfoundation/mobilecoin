#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around mint-auditor integration_test.py to set up environment for testing.
#

set -e

usage()
{
    echo "Usage --token-id <num>"
    echo "    --token-id - token id to test"
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
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

is_set token_id
is_set NAMESPACE


echo "-- Install python packages"
echo ""
pip3 install grpcio grpcio-tools

echo ""
echo "-- Set up proto files"
echo ""

pushd /test/mint-auditor || exit 1

python3 -m grpc_tools.protoc \
    -I"/proto/api" \
    --python_out=. \
    "/proto/api/external.proto"

python3 -m grpc_tools.protoc \
    -I"/proto/api" \
    --python_out=. \
    "/proto/api/blockchain.proto"

python3 -m grpc_tools.protoc \
    -I"/proto/api" \
    -I"/proto/mobilecoind" \
    -I"/proto/consensus" \
    --python_out=. --grpc_python_out=. \
    "/proto/mobilecoind/mobilecoind_api.proto"

python3 -m grpc_tools.protoc \
    -I"/proto/mint-auditor" \
    --python_out=. --grpc_python_out=. \
    "/proto/mint-auditor/mint_auditor.proto"

echo ""
echo "-- Run integration_test.py"
echo ""
token_signer_key="/minting-keys/token${token_id}_signer.private.pem"

python3 integration_test.py \
    --mobilecoind-addr "mobilecoind:3229" \
    --mint-auditor-addr "mobilecoind-mint-auditor:7774" \
    --mint-client-bin /usr/local/bin/mc-consensus-mint-client \
    --node-url "mc://node1.${NAMESPACE}.infradev.mobilecoin.com/" \
    --mint-signing-key "${token_signer_key}"

popd >/dev/null || exit 1
