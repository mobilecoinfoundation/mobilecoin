#!/bin/bash

# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Publish protobuf definition updates to buf.build
#
# Not that tags cannot be overwritten, so tag only after a release is cut.
#
# Usage:
#     # Push a revision for SDKs/clients.
#     tools/buf_push.sh
#
#     # Tag a release after it is cut.
#     tools/buf_push.sh --tag=1.2.3

set -e  # exit on error

# NB: protos in mobilecoind and fog depend on other dirs in this list,
# so be mindful of dependency order; a sorted list happens to work.
DIRS=(
    api/proto
    attest/api/proto
    consensus/api/proto
    fog/api/proto
    fog/report/api/proto
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
