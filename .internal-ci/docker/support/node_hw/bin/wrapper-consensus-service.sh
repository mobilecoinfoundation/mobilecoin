#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# wrapper-consensus-service.sh - Wrapper script around consensus-service to
# make sure required services have started and stayed running.

# is_set <variable name>
# check to see if required variable has a value
is_set()
{
    var_name="${1}"
    if [ -z "${!var_name}" ]
    then
        echo "${var_name} is not set."
        exit 1
    fi
}

# super_status <service>
# get status from a supervisord service
super_status()
{
    supervisorctl status "${1}" | awk '{print $2}'
}

# Required vars
is_set MC_BRANCH
is_set MC_PEER_RESPONDER_ID
is_set MC_CLIENT_RESPONDER_ID
is_set MC_MSG_SIGNER_KEY

# Default vars
export MC_PEER_LISTEN_URI=${MC_PEER_LISTEN_URI:-"insecure-mcp://0.0.0.0:8443/"}
export MC_CLIENT_LISTEN_URI=${MC_CLIENT_LISTEN_URI:-"insecure-mc://0.0.0.0:3223/"}
export MC_ADMIN_LISTEN_URI=${MC_ADMIN_LISTEN_URI:-"insecure-mca://127.0.0.1:8001/"}
export MC_NETWORK=${MC_NETWORK:-"/config/network.json"}
export MC_TOKENS=${MC_TOKENS:-"/config/tokens.signed.json"}
export MC_LEDGER_PATH=${MC_LEDGER_PATH:-"/ledger"}
export MC_SCP_DEBUG_DUMP=${MC_SCP_DEBUG_DUMP:-"/scp-debug-dump"}
export MC_SEALED_BLOCK_SIGNING_KEY=${MC_SEALED_BLOCK_SIGNING_KEY:-"/sealed/block-signing-key"}
export MC_SENTRY_DSN=${CONSENSUS_SERVICE_SENTRY_DSN}

# Optional vars - sentry/logging
# CONSENSUS_SERVICE_SENTRY_DSN
# MC_LOG_UDP_JSON

# Run consensus-service with ENV var options
/usr/bin/consensus-service
