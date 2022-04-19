#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate seeds for initial and fog wallets.

set -e

BASE_PATH="${BASE_PATH:-.tmp/wallet_seeds}"

mkdir -p "${BASE_PATH}"

if [[ ! -f "${BASE_PATH}/initial_keys_seed" ]] && [[ ! -s "${BASE_PATH}/initial_keys_seed" ]]
then
    echo "--- Create initial keys seed ---"
    INITIAL_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${INITIAL_KEYS_SEED}"
    echo -n "${INITIAL_KEYS_SEED}" > "${BASE_PATH}/initial_keys_seed"
else
    echo "--- initial keys seed already exists ---"
fi
sha256sum "${BASE_PATH}/initial_keys_seed"

if [[ ! -f "${BASE_PATH}/fog_keys_seed" ]] && [[ ! -s "${BASE_PATH}/fog_keys_seed" ]]
then
    echo "--- Create fog keys seed ---"
    FOG_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${FOG_KEYS_SEED}"
    echo -n "${FOG_KEYS_SEED}" > .tmp/wallet_seeds/fog_keys_seed
else
    echo "--- fog keys seed already exists ---"
fi
sha256sum "${BASE_PATH}/fog_keys_seed"
