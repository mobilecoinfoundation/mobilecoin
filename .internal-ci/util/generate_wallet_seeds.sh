#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generate and output seeds for initial and fog wallets.
# Checks for to see if seed values exist. If not generate a random seed values.

# CBB make this a loop instead of copy/paste key

set -e

gen_seed()
{
    openssl rand -hex 32
}

BASE_PATH="${BASE_PATH:-.tmp/seeds}"
mkdir -p "${BASE_PATH}"

# if INITIAL_KEYS_SEED is set then use that.
if [[ -n "${INITIAL_KEYS_SEED}" ]]
then
    echo "-- Using INITIAL_KEYS_SEED variable"
elif [[ ! -f "${BASE_PATH}/INITIAL_KEYS_SEED" ]] && [[ ! -s "${BASE_PATH}/INITIAL_KEYS_SEED" ]]
then
        # we didn't find the seed value or existing files - so create them
    echo "-- Create initial keys seed at ${BASE_PATH}/INITIAL_KEYS_SEED"
    INITIAL_KEYS_SEED=$(gen_seed)
else
    echo "-- Initial ${BASE_PATH}/INITIAL_KEYS_SEED already exists"
    INITIAL_KEYS_SEED=$(cat "${BASE_PATH}/INITIAL_KEYS_SEED")
fi
# Write key
echo -n "${INITIAL_KEYS_SEED}" > "${BASE_PATH}/INITIAL_KEYS_SEED"


# if FOG_KEYS_SEED is set then use that.
if [[ -n "${FOG_KEYS_SEED}" ]]
then
    echo "-- Using FOG_KEYS_SEED variable"
elif [[ ! -f "${BASE_PATH}/FOG_KEYS_SEED" ]] && [[ ! -s "${BASE_PATH}/FOG_KEYS_SEED" ]]
then
    # we didn't find the seed value or existing files - so create them
    echo "-- Create initial keys seed at ${BASE_PATH}/FOG_KEYS_SEED"
    FOG_KEYS_SEED=$(gen_seed)
else
    echo "-- Initial ${BASE_PATH}/FOG_KEYS_SEED already exists"
    FOG_KEYS_SEED=$(cat "${BASE_PATH}/FOG_KEYS_SEED")
fi
# Write key
echo -n "${FOG_KEYS_SEED}" > "${BASE_PATH}/FOG_KEYS_SEED"

# if MNEMONIC_KEYS_SEED is set then use that.
if [[ -n "${MNEMONIC_KEYS_SEED}" ]]
then
    echo "-- Using MNEMONIC_KEYS_SEED variable"
elif [[ ! -f "${BASE_PATH}/MNEMONIC_KEYS_SEED" ]] && [[ ! -s "${BASE_PATH}/MNEMONIC_KEYS_SEED" ]]
then
    # we didn't find the seed value or existing files - so create them
    echo "-- Create initial keys seed at ${BASE_PATH}/MNEMONIC_KEYS_SEED"
    MNEMONIC_KEYS_SEED=$(gen_seed)
else
    echo "-- Initial ${BASE_PATH}/MNEMONIC_KEYS_SEED already exists"
    MNEMONIC_KEYS_SEED=$(cat "${BASE_PATH}/MNEMONIC_KEYS_SEED")
fi
# Write key
echo -n "${MNEMONIC_KEYS_SEED}" > "${BASE_PATH}/MNEMONIC_KEYS_SEED"

# if MNEMONIC_FOG_KEYS_SEED is set then use that.
if [[ -n "${MNEMONIC_FOG_KEYS_SEED}" ]]
then
    echo "-- Using MNEMONIC_FOG_KEYS_SEED variable"
elif [[ ! -f "${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED" ]] && [[ ! -s "${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED" ]]
then
    # we didn't find the seed value or existing files - so create them
    echo "-- Create initial keys seed at ${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED"
    MNEMONIC_FOG_KEYS_SEED=$(gen_seed)
else
    echo "-- Initial ${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED already exists"
    MNEMONIC_FOG_KEYS_SEED=$(cat "${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED")
fi
# Write key
echo -n "${MNEMONIC_FOG_KEYS_SEED}" > "${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED"

# Echo checksum
echo "--- initial_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/INITIAL_KEYS_SEED"

echo "--- fog_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/FOG_KEYS_SEED"

echo "--- mnemonic_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/MNEMONIC_KEYS_SEED"

echo "--- mnemonic_fog_keys_seed sha256 ---"
sha256sum "${BASE_PATH}/MNEMONIC_FOG_KEYS_SEED"
