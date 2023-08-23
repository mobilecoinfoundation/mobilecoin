#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -eo pipefail

if [[ -n "${INITIAL_KEYS_SEED}" ]]
then
    generate_origin_data.sh
fi

/usr/local/bin/ledger-download.sh /data

exec "$@"
