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

VERSION="$1"
if [ "$VERSION" = "" ]; then
    VERSION="1"
fi

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
BASE_PATH="${BASE_PATH:-.tmp}"
minting_path="${BASE_PATH}/seeds/minting"

# check for required files
tokens_file="${location}/tokens.v${VERSION}.base.json"
exists "${tokens_file}"

exists "${minting_path}/minter1_governor.public.pem"
sha256sum "${minting_path}/minter1_governor.public.pem"

exists "${minting_path}/minting_trust_root.private.pem"
sha256sum "${minting_path}/minting_trust_root.private.pem"

# Grab base json
json=$(cat "${tokens_file}")

# Set minter1 pub keys and threshold
minter1_governor=$(cat "${minting_path}/minter1_governor.public.pem")
if [ "$VERSION" = "1" ]; then
    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.signers) |= \"${minter1_governor}\"")
    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.threshold) |= 1")
elif [ "$VERSION" = "2" ]; then
    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.signer_identities.minter1_governor) |= \"${minter1_governor}\"")
    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.signer_set.signers) |= [{\"type\": \"Single\", \"identity\": \"minter1_governor\"}]")
    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == 1) | .governors.signer_set.threshold) |= 1")
else
    echo "Unknown version $VERSION"
    exit 1
fi

#output unsigned tokens
echo "$json" | jq . > .tmp/tokens.json

# Sign tokens file
echo "Signing tokens file"
cat .tmp/tokens.json
mc-consensus-mint-client sign-governors --tokens "${BASE_PATH}/tokens.json" \
    --signing-key "${minting_path}/minting_trust_root.private.pem" \
    --output-json "${BASE_PATH}/tokens.signed.json"  >/dev/null
