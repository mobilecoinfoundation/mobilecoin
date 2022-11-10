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
MINTING_BASE_PATH="${MINTING_BASE_PATH:-.tmp/minting}"

# check for required files
exists "${location}/tokens.base.json"

# Grab base json
json=$(cat "${location}/tokens.base.json")
token_ids=$(echo "${json}" | jq -r '.tokens[].token_id')

for id in ${token_ids}
do
    if [[ ${id} -eq 0 ]]
    then
        echo "Found token_id 0 - nothing to do."
        continue
    fi

    echo "Token ID: ${id} - Checking for governor ed25519 keys"
    threshold=0
    governors=""

    files="${MINTING_BASE_PATH}/token_${id}_governor_*"

    # concat governor keys
    for g in $files
    do
        if [[ "${g}" =~ "public" ]]
        then
            echo "-- Found governor: ${g}, adding it to the governors list."
            sha256sum "${g}"

            governors="${governors}$(cat "${g}")"
            ((threshold+=1))
        fi
    done


    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.signers) |= \"${governors}\"")

    json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.threshold) |= ${threshold}")
done

#output unsigned tokens
echo "$json" | jq . > "${BASE_PATH}/tokens.json"

echo "Checking for minting_trust_root ed25519 keys"
exists "${MINTING_BASE_PATH}/minting_trust_root.private.pem"
sha256sum "${MINTING_BASE_PATH}/minting_trust_root.private.pem"

# Sign tokens file
echo "Signing the tokens file"
mc-consensus-mint-client sign-governors --tokens "${BASE_PATH}/tokens.json" \
    --signing-key "${MINTING_BASE_PATH}/minting_trust_root.private.pem" \
    --output-json "${BASE_PATH}/tokens.signed.json"  >/dev/null

cat "${BASE_PATH}/tokens.signed.json"
