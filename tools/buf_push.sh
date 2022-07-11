#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation

set -e  # exit on error

# NB: protos in mobilecoind and fog depend on other dirs in this list,
# so be mindful of dependency order; a sorted list happens to work.
DIRS=(
    api/proto
    attest/api/proto
    consensus/api/proto
    fog/api/proto
    fog/report/api/proto
    mint-auditor/api/proto
    mobilecoind/api/proto
    util/grpc/proto
)

for dir in ${DIRS[@]}
do
    echo "Pushing $dir..."
    pushd $dir > /dev/null
    # Propagate script args to buf push
    buf mod update && buf build && buf push "$@"
    popd > /dev/null
done
