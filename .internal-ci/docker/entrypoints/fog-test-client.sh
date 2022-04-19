#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Entrypoint script to set up fog-test-client environment.
#

function parse_url()
{
    # extract the protocol
    proto=$(echo "$1" | grep :// | sed -e's,^\(.*://\).*,\1,g')
    # remove the protocol
    url="${1/$proto/}"
    # extract the user (if any)
    user=$(echo "${url}" | grep @ | cut -d@ -f1)
    # extract the host and port
    hostport=$(echo "${url/$user@/}" | cut -d/ -f1)
    # by request host without port
    host="${hostport/:*/}"
    # by request - try to extract the port
    port=$(echo "${hostport}" | sed -e 's,^.*:,:,g' -e 's,.*:\([0-9]*\).*,\1,g' -e 's,[^0-9],,g')
    # extract the path (if any)
    path=$(echo "${url}" | grep / | cut -d/ -f2-)
}

# check to see if a var is set. Exit 1 if not set.
#  1: Variable name
function is_set()
{
    var_name="${1}"

    if [ -z "${!var_name}" ]; then
        echo "${var_name} is not set."
        exit 1
    fi
}

is_set FOG_LEDGER
is_set FOG_VIEW
is_set CONSENSUS_VALIDATORS

if [ -n "${CLIENT_AUTH_TOKEN_SECRET}" ]
then
    echo "Generating Client Auth Creds"
    us="user1"
    pw=$(mc-util-grpc-token-generator --shared-secret "${CLIENT_AUTH_TOKEN_SECRET}" --username user1 | grep Password: | awk '{print $2}')

    echo "Re-exporting FOG_LEDGER with user/token"
    parse_url "${FOG_LEDGER}"
    export FOG_LEDGER="${proto}${us}:${pw}@${host}:${port}/${path}"

    echo "Re-exporting FOG_VIEW with user/token"
    parse_url "${FOG_VIEW}"
    export FOG_VIEW="${proto}${us}:${pw}@${host}:${port}/${path}"
fi

exec "$@"
