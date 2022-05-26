#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Copy a set of keys from one folder to another - useful for grabbing a subset of keys for drain/test tools.
#

set -e

usage()
{
    echo "Usage:"
    echo "${0} --src /tmp/sample_keys/keys --dst /tmp/smaller_key_set --start 0 --end 6"
    echo "    --src - source keys directory (keys to drain)"
    echo "    --dst - destination keys directory (keys to fund)"
    echo "    --start - key number to start"
    echo "    --end - key number to end"
}

is_set()
{
    var_name="${1}"
    if [ -z "${!var_name}" ]
    then
        echo "${var_name} is not set."
        usage
        exit 1
    fi
}

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --src )
            src="${2}"
            shift 2
            ;;
        --dst )
            dst="${2}"
            shift 2
            ;;
        --start )
            start="${2}"
            shift 2
            ;;
        --end )
            end="${2}"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

is_set src
is_set dst
is_set start
is_set end

num_of_keys=$((end - start + 1))

mkdir -p "${dst}"

echo "-- Copy ${num_of_keys} account keys from ${src} to ${dst}"
echo ""
for i in $(seq "${start}" "${end}")
do
    echo "-- copy key ${i}"
    find "${src}" -name "*_${i}.*" -exec cp {} "${dst}" \;
done
