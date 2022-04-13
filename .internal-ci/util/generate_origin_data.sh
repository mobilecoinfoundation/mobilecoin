#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# populate_origin_data.sh
#
# Generate ledger/data.mdb for development builds
# TODO: Restore ledger/data.mdb for persistent builds.

set -e

is_set()
{
    var_name="${1}"

    if [ -z "${!var_name}" ]; then
        echo "${var_name} is not set."
        exit 1
    fi
}

BASE_PATH=${BASE_PATH:-/tmp}
is_set INITIAL_KEYS_SEED

mkdir -p "${BASE_PATH}/sample_data/ledger"
mkdir -p "${BASE_PATH}/sample_data/keys"
mkdir -p "${BASE_PATH}/sample_data/fog_keys"

pushd "${BASE_PATH}/sample_data" > /dev/null || exit 1

echo "-- Generate initial keys"
sample-keys --num 1000 \
    --seed "${INITIAL_KEYS_SEED}"

if [[ "${INITIALIZE_LEDGER}" == "true" ]]
then
    echo ""
    echo "-- Initialize ledger"
    generate-sample-ledger --txs 100
fi

if [[ -n "${FOG_KEYS_SEED}" ]]
then
    is_set FOG_REPORT_SIGNING_CA_CERT_PATH
    is_set FOG_REPORT_URL

    echo ""
    echo "-- Generate keys for fog-distribution"

    sample-keys --num 500 \
        --seed "${FOG_KEYS_SEED}" \
        --fog-report-url "${FOG_REPORT_URL}" \
        --fog-authority-root "${FOG_REPORT_SIGNING_CA_CERT_PATH}" \
        --output-dir ./fog_keys

    rm -f ./ledger/lock.mdb
fi

popd > /dev/null || exit 1
