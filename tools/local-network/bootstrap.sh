#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# This script is intended to make sample data (bootstrapped ledger) suitable
# for local-networktests.
#
# The data is placed in target/sample_data
# The parameters to the script are:
# - NUM_KEYS
# - NUM_UTXOS_PER_ACCOUNT
#
# The tool attempts to avoid rebootstrapping if it doesn't appear necessary,
# which means:
# - target/sample_data already exists (and conf.json exists)
# - conf.json has the same parameters as the user requrests
#
# The tool reruns bootstrap and records a new conf.json file
# jq must be installed to use the tool

set -e

# Change to the project's root directory
cd $(dirname "$0")/../..
echo "PWD: $PWD"
PROJECT_ROOT=$PWD

# Collect parameters for the bootstrap
NUM_KEYS=${NUM_KEYS=20}
NUM_UTXOS_PER_ACCOUNT=${NUM_UTXOS_PER_ACCOUNT=100}
MAX_TOKEN_ID=${MAX_TOKEN_ID=0}

TARGET="./target/sample_data"

if [ -d $TARGET ]; then
    echo "Found pre-existing sample_data..."
    if [ -f $TARGET/conf.json ]; then
        echo "Found sample_data/conf.json..."
        jq < $TARGET/conf.json

        OLD_NUM_KEYS=$(jq .NUM_KEYS < $TARGET/conf.json)
        OLD_NUM_UTXOS=$(jq .NUM_UTXOS_PER_ACCOUNT < $TARGET/conf.json)
        OLD_MAX_TOKEN_ID=$(jq .MAX_TOKEN_ID < $TARGET/conf.json)
        if [ \
            "$OLD_NUM_KEYS" -eq "$NUM_KEYS" -a \
            "$OLD_NUM_UTXOS" -eq "$NUM_UTXOS_PER_ACCOUNT" -a \
            "$OLD_MAX_TOKEN_ID" -eq "$MAX_TOKEN_ID" \
        ]; then
            echo "Skipping bootstrap"
            exit 0
        else
            echo "Conf has changed, re-boostrapping"
        fi
    else
        echo "No conf.json... re-bootstrapping"
    fi
fi

if [ -d $TARGET/ledger ]; then
    echo "Can't bootstrap on top of pre-existing ledger, please delete $TARGET to start from scratch."
    exit 1
fi

mkdir -p $TARGET
cd $TARGET

set -x

cargo run \
    -p mc-util-keyfile \
    --bin sample-keys \
    --release \
    -- \
    --num $NUM_KEYS \
    --output-dir keys
cargo run \
    -p mc-util-generate-sample-ledger \
    --bin generate-sample-ledger \
    --release \
    -- \
    --txs $NUM_UTXOS_PER_ACCOUNT \
    --max-token-id $MAX_TOKEN_ID
