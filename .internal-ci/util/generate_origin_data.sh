#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate ledger/data.mdb, initial/fog keys for development builds
#
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
mkdir -p "${BASE_PATH}/sample_data/mnemonic_keys"
mkdir -p "${BASE_PATH}/sample_data/mnemonic_fog_keys"

pushd "${BASE_PATH}/sample_data" > /dev/null || exit 1

echo "-- Generate initial keys"
/util/sample-keys.1.1.3 --num 1000 \
    --seed "${INITIAL_KEYS_SEED}" \
    --output-dir ./keys

echo "-- Generate b58pub files for initial keys"
for i in {0..999}
do
    read-pubfile --pubfile "./keys/account_keys_${i}.pub" \
        --out-b58 "./keys/account_keys_${i}.b58pub" >/dev/null 2>&1
done

if [[ "${INITIALIZE_LEDGER}" == "true" ]]
then
    echo ""
    echo "-- Initialize ledger"
    generate-sample-ledger --txs 100
    rm -f ./ledger/lock.mdb
fi

if [[ -n "${FOG_KEYS_SEED}" ]]
then
    is_set FOG_REPORT_SIGNING_CA_CERT_PATH
    is_set FOG_REPORT_URL

    echo ""
    echo "-- Generate keys for fog-distribution"

    /util/sample-keys.1.1.3 --num 500 \
        --seed "${FOG_KEYS_SEED}" \
        --fog-report-url "${FOG_REPORT_URL}" \
        --fog-authority-root "${FOG_REPORT_SIGNING_CA_CERT_PATH}" \
        --output-dir ./fog_keys

    echo "-- Generate b58pub files for fog keys"
    for i in {0..499}
    do
        read-pubfile --pubfile "./fog_keys/account_keys_${i}.pub" \
            --out-b58 "./fog_keys/account_keys_${i}.b58pub" >/dev/null 2>&1
    done
fi

if [[ -n "${MNEMONIC_KEYS_SEED}" ]]
then
    echo ""
    echo "-- Generate mnemonic non-fog keys"

    sample-keys --num 6 \
        --seed "${MNEMONIC_KEYS_SEED}" \
        --output-dir ./mnemonic_keys
fi

if [[ -n "${MNEMONIC_FOG_KEYS_SEED}" ]]
then
    is_set FOG_REPORT_SIGNING_CA_CERT_PATH
    is_set FOG_REPORT_URL

    echo ""
    echo "-- Generate mnemonic fog keys"

    sample-keys --num 6 \
        --seed "${MNEMONIC_FOG_KEYS_SEED}" \
        --fog-report-url "${FOG_REPORT_URL}" \
        --fog-authority-root "${FOG_REPORT_SIGNING_CA_CERT_PATH}" \
        --output-dir ./mnemonic_fog_keys
fi

popd > /dev/null || exit 1
