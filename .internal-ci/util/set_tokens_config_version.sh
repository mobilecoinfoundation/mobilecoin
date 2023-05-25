#!/bin/bash
# Copyright (c) 2018-2023 The MobileCoin Foundation

# Select the correct tokens file to use based on release version.

set -eu

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# shellcheck source=.shared_functions
source "${location}/.shared_functions"

network=$(get_network_tier "${1}")
major=$(get_major_version "${1}")

echo "Found network ${network}" >&2
echo "Found major version ${major}" >&2

# 0 - dev use V2
# 1|2|3 - use V1 - note 1 doesn't consume
# 4 or greater use v2
if [[ ${major} -eq 0 ]]
then
    version="V2"
elif [[ ${major} -ge 1 ]] && [[ ${major} -le 3 ]]
then
    version="V1"
elif [[ ${major} -ge 4 ]]
then
    version="V2"
else
    echo "Major version is invalid? ${1} ${major}" >&2
    exit 1
fi

# ^^ upper case network
token_json="${network^^}_TOKENS_CONFIG_${version}_JSON"
echo "Using ${token_json}" >&2
# ! use value as the variable name
echo "${!token_json}"
