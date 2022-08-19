#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# entrypoint script for the go-grpc-gateway (json -> grpc)
#

# exit if anything fails.
if [[ ${ENTRYPOINT_DEBUG} == "true" ]]; then
    set -ex
else
    set -e
fi

/usr/bin/go-grpc-gateway \
    -grpc-server-endpoint "${GRPC_SERVER_ENDPOINT}" \
    "${GRPC_INSECURE}" \
    -http-server-listen "${HTTP_SERVER_LISTEN}"

wait -n
