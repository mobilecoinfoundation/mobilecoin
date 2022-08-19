#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around the mobilecoind-json integration_test.py to set up environment for testing.
#

set -e
usage()
{
    echo "Usage --key-dir <dir>"
    echo "    --key-dir - source keys directory (keys to test)"
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
        *)
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

is_set key_dir
is_set NAMESPACE

# This uses some of the same lib py files as mobilecoind tests.
strategies_dir=/tmp/mobilecoind-json/strategies
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
    -I"/proto/api" \
    -I"/proto/mobilecoind" \
    -I"/proto/consensus" \
    -I"/proto/mint-auditor" \
    --python_out=. \
    --grpc_python_out=. \
    /proto/api/external.proto \
    /proto/api/blockchain.proto \
    /proto/mobilecoind/mobilecoind_api.proto \
    /proto/mint-auditor/mint_auditor.proto

echo ""
echo "-- Run integration_test.py"
echo ""
python3 /test/mobilecoind-json/integration_test.py \
    --key-dir "${key_dir}" \
    --mobilecoind-json-url http://mobilecoind-json:9090

popd >/dev/null || exit 1
