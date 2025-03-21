#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around the mobilecoind test_client.py to set up environment for testing.
#

set -e

strategies_dir=/tmp/mobilecoind/strategies
keys_dir="${strategies_dir}/keys"

mkdir -p "${keys_dir}"

echo "-- Copy account keys"
echo ""
for i in {0..4}
do
    # shellcheck disable=SC2086
    cp /tmp/sample_data/keys/*_${i}.* "${keys_dir}"
done

cp /test/mobilecoind/strategies/* "${strategies_dir}"

pushd "${strategies_dir}" >/dev/null || exit 1

echo "-- Install requirements"
echo ""
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

echo ""
echo "-- Set up proto files"
echo ""

python3 -m grpc_tools.protoc \
    -I"/proto/api" \
    -I"/proto/mobilecoind" \
    -I"/proto/consensus" \
    -I"/proto/attest" \
    -I"/proto/fog" \
    --python_out=. \
    --grpc_python_out=. \
    /proto/api/external.proto \
    /proto/api/blockchain.proto \
    /proto/api/quorum_set.proto \
    /proto/api/watcher.proto \
    /proto/attest/attest.proto \
    /proto/fog/fog_common.proto \
    /proto/fog/ledger.proto \
    /proto/mobilecoind/mobilecoind_api.proto \
    /proto/consensus/consensus_common.proto

echo ""
echo "-- Run test_client.py"
echo ""
python3 test_client.py \
    --key-dir "${keys_dir}" \
    --mobilecoind-host "mobilecoind" \
    --mobilecoind-port 3229

popd >/dev/null || exit 1
