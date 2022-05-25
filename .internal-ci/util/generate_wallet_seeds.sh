#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate and output seeds for initial and fog wallets.
# Checks for to see if seed values exist. If not generate a random seed values.

# CBB make this a loop instead of copy/paste key

set -e

BASE_PATH="${BASE_PATH:-.tmp/seeds}"

mkdir -p "${BASE_PATH}"

if [[ ! -f "${BASE_PATH}/initial_keys_seed" ]] && [[ ! -s "${BASE_PATH}/initial_keys_seed" ]]
then
    echo "--- Create initial keys seed ---"
    INITIAL_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${INITIAL_KEYS_SEED}"
    echo -n "${INITIAL_KEYS_SEED}" > "${BASE_PATH}/initial_keys_seed"
else
    echo "--- initial keys seed already exists ---"
    INITIAL_KEYS_SEED=$(cat "${BASE_PATH}/initial_keys_seed")
fi

if [[ ! -f "${BASE_PATH}/fog_keys_seed" ]] && [[ ! -s "${BASE_PATH}/fog_keys_seed" ]]
then
    echo "--- Create fog keys seed ---"
    FOG_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${FOG_KEYS_SEED}"
    echo -n "${FOG_KEYS_SEED}" > "${BASE_PATH}/fog_keys_seed"
else
    echo "--- fog keys seed already exists ---"
    FOG_KEYS_SEED=$(cat "${BASE_PATH}/fog_keys_seed")
fi

if [[ ! -f "${BASE_PATH}/mnemonic_keys_seed" ]] && [[ ! -s "${BASE_PATH}/mnemonic_keys_seed" ]]
then
    echo "--- Create mnemonic keys seed ---"
    MNEMONIC_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${MNEMONIC_KEYS_SEED}"
    echo -n "${MNEMONIC_KEYS_SEED}" > "${BASE_PATH}/mnemonic_keys_seed"
else
    echo "--- mnemonic keys seed already exists ---"
    MNEMONIC_KEYS_SEED=$(cat "${BASE_PATH}/mnemonic_keys_seed")
fi

if [[ ! -f "${BASE_PATH}/mnemonic_fog_keys_seed" ]] && [[ ! -s "${BASE_PATH}/mnemonic_fog_keys_seed" ]]
then
    echo "--- Create mnemonic fog keys seed ---"
    MNEMONIC_FOG_KEYS_SEED=$(openssl rand -hex 32)
    echo "::add-mask::${MNEMONIC_FOG_KEYS_SEED}"
    echo -n "${MNEMONIC_FOG_KEYS_SEED}" > "${BASE_PATH}/mnemonic_fog_keys_seed"
else
    echo "--- mnemonic fog keys seed already exists ---"
    MNEMONIC_FOG_KEYS_SEED=$(cat "${BASE_PATH}/mnemonic_fog_keys_seed")
fi


echo "::add-mask::${INITIAL_KEYS_SEED}"
echo "::set-output name=initial_keys_seed::${INITIAL_KEYS_SEED}"
echo "--- initial_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/initial_keys_seed"

echo "::add-mask::${FOG_KEYS_SEED}"
echo "::set-output name=fog_keys_seed::${FOG_KEYS_SEED}"
echo "--- fog_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/fog_keys_seed"

echo "::add-mask::${MNEMONIC_KEYS_SEED}"
echo "::set-output name=mnemonic_keys_seed::${MNEMONIC_KEYS_SEED}"
echo "--- mnemonic_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/mnemonic_keys_seed"

echo "::add-mask::${MNEMONIC_FOG_KEYS_SEED}"
echo "::set-output name=mnemonic_fog_keys_seed::${MNEMONIC_FOG_KEYS_SEED}"
echo "--- mnemonic_fog_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/mnemonic_fog_keys_seed"
