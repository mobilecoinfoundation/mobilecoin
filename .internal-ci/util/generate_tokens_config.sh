#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Create tokens.json with generated governor keys.

set -e

exists()
{
    if [[ ! -f "${1}" ]]
    then
        echo "${1} doesn't exist"
        exit 1
    fi
}

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BASE_PATH="${BASE_PATH:-.tmp}"
minting_path="${BASE_PATH}/seeds/minting"

# check for required files
exists "${location}/tokens.base.json"

exists "${minting_path}/minter1_governor.public.pem"
sha256sum "${minting_path}/minter1_governor.public.pem"

exists "${minting_path}/minting_trust_root.private.pem"
sha256sum "${minting_path}/minting_trust_root.private.pem"

# Grab base json
json=$(cat "${location}/tokens.base.json")

# Set minter1 pub keys and threshold
minter1_governor=$(cat "${minting_path}/minter1_governor.public.pem")
json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.signers) |= \"${minter1_governor}\"")
json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.threshold) |= 1")

#output unsigned tokens
echo "$json" | jq . > .tmp/tokens.json

# Sign tokens file
echo "Signing tokens file"
mc-consensus-mint-client sign-governors --tokens "${BASE_PATH}/tokens.json" \
    --signing-key "${minting_path}/minting_trust_root.private.pem" \
    --output-json "${BASE_PATH}/tokens.signed.json"  >/dev/null
