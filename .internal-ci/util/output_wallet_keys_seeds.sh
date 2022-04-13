#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
set -e

BASE_PATH="${BASE_PATH:-.tmp/wallet_seeds}"
INITIAL_KEYS_SEED=$(cat "${BASE_PATH}/initial_keys_seed")
FOG_KEYS_SEED=$(cat "${BASE_PATH}/fog_keys_seed")

if [[ -z "${INITIAL_KEYS_SEED}" ]] || [[ -z "${FOG_KEYS_SEED}" ]]
then
    echo "one or both seed files are empty! Restart build and try again."
    exit 1
fi

echo "--- get initial_keys_seed ---"
echo "::add-mask::${INITIAL_KEYS_SEED}"
echo "::set-output name=initial_keys_seed::${INITIAL_KEYS_SEED}"
sha256sum "${BASE_PATH}/initial_keys_seed"

echo "--- get fog_keys_seed ---"
echo "::add-mask::${FOG_KEYS_SEED}"
echo "::set-output name=fog_keys_seed::${FOG_KEYS_SEED}"
sha256sum "${BASE_PATH}/fog_keys_seed"
