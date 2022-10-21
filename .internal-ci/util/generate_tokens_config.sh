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

# Grab base json
json=$(cat "${tokens_file}")
token_ids=$(echo "${json}" | jq -r '.tokens[].token_id')

for id in ${token_ids}
do
    if [[ ${id} -eq 0 ]]
    then
        echo "Found token_id 0 - nothing to do."
        continue
    fi

    echo "Token ID: ${id} - Checking for governor ed25519 keys"
    exists "${minting_path}/minter${id}_governor.public.pem"
    sha256sum "${minting_path}/minter8192_governor.public.pem"

    echo "Token ID: ${id} - Add governor signer pub keys and threshold to json"
    minter_governor=$(cat "${minting_path}/minter${id}_governor.public.pem")

    if [ "$VERSION" = "1" ]; then
        json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.signers) |= \"${minter_governor}\"")
        json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.threshold) |= 1")
    elif [ "$VERSION" = "2" ]; then
        json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.signer_identities.minter1_governor) |= \"${minter_governor}\"")
        json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.signer_set.signers) |= [{\"type\": \"Single\", \"identity\": \"minter1_governor\"}]")
        json=$(echo "${json}" | jq "(.tokens[] | select(.token_id == ${id}) | .governors.signer_set.threshold) |= 1")
    else
        echo "Unknown version $VERSION"
        exit 1
    fi
done

#output unsigned tokens
echo "$json" | jq . > "${BASE_PATH}/tokens.json"

echo "Generated tokens file:"
cat "${BASE_PATH}/tokens.json"
echo

echo "Checking for minting_trust_root ed25519 keys"
exists "${minting_path}/minting_trust_root.private.pem"
sha256sum "${minting_path}/minting_trust_root.private.pem"

# Sign tokens file
echo "Signing tokens file"
mc-consensus-mint-client sign-governors --tokens "${BASE_PATH}/tokens.json" \
    --signing-key "${minting_path}/minting_trust_root.private.pem" \
    --output-json "${BASE_PATH}/tokens.signed.json"  >/dev/null

cat "${BASE_PATH}/tokens.signed.json"
