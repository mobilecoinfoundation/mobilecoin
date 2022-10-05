#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Wrapper around fog-distribution binary to add some simple checks and clean defaults.
#

set -e

run_file=/var/tmp/.fog-distribution-already-ran

if [ -f "${run_file}" ]
then
    echo "-- Cowardly refusing to run fog-distribution a second time."
    exit 0
fi

touch "${run_file}"

fog-distribution --sample-data-dir /tmp/sample_data \
    --peer "mc://node1.${NAMESPACE}.development.mobilecoin.com:443" \
    --peer "mc://node2.${NAMESPACE}.development.mobilecoin.com:443" \
    --peer "mc://node3.${NAMESPACE}.development.mobilecoin.com:443" \
    --num-tx-to-send 20


# assumes
# /tmp/sample_data/keys - path to init keys where funds are coming from
# /tmp/sample_data/fog_keys - path to destination keys
