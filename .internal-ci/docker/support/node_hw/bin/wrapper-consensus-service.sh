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
is_set MC_IAS_API_KEY
is_set MC_IAS_SPID

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

# Check to see if aesm service is ready.
aesm_socket=/var/run/aesmd/aesm.socket
aesm=0
ledger=0
echo "mc.app:wrapper-consensus-service Wait for ledger-distribution and aesm service to become ready"
while [[ "${aesm}" -le 1 ]] && [[ "${ledger}" -le 1 ]]
do
    sleep 10

    aesm_status=$(super_status aesm-service)
    ledger_distribution_status=$(super_status ledger-distribution)

    # does the aesm socket exist, is the service in RUNNING?
    if [[ -S "${aesm_socket}" ]] && [[ "${aesm_status}" == "RUNNING" ]]
    then
        echo "mc.app:wrapper-consensus-service aesm-service is RUNNING and ${aesm_socket} found - success ${aesm}"
        ((aesm++))
    else
        echo "mc.app:wrapper-consensus-service aesm-service is not RUNNING or ${aesm_socket} not found - reset counter"
        aesm=0
    fi

    # is ledger-distribution running?
    if [[ "${ledger_distribution_status}" == "RUNNING" ]]
    then
        echo "mc.app:wrapper-consensus-service ledger-distribution is RUNNING - success ${ledger}"
        ((ledger++))
    else
        echo "mc.app:wrapper-consensus-service ledger-distribution is not RUNNING - reset counter"
    fi
done

# Run consensus-service with ENV var options
/usr/bin/consensus-service
