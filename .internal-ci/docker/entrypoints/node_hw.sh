#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Entrypoint script for node_hw (consensus and friends).
#

# Optional Load vars from .env file
# DOTENV_CONFIG_FILE
#   default /config/.env

# Required Vars
# MC_BRANCH - mobilecoin network for monitoring/logs
#   example test (for testnet), prod (for mainnet), alpha

# Required Vars consensus-service
# MC_PEER_RESPONDER_ID - fully qualified name:port that fronts the peer port
#   example peer1.test.mobilecoin.com:443
# MC_CLIENT_RESPONDER_ID - fully qualified name:port that fronts the client port
#   example client1.test.mobilecoin.com:443
# MC_MSG_SIGNER_KEY - private key for signing messages
# MC_IAS_API_KEY - Intel IAS API key
# MC_IAS_SPID - Intel IAS spid

# Optional Vars consensus-service
# MC_TX_SOURCE_URL - http url to retrieve archive (s3) blocks for node
#   example https://s3-eu-central-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/
# MC_PEER_LISTEN_URI
#   default insecure-mcp://0.0.0.0:8443/
#   tls example mcp://0.0.0.0:8443/?tls-chain=cert.pem&tls-key=key.pem
# MC_CLIENT_LISTEN_URI
#   default insecure-mc://0.0.0.0:3223/
#   tls example mc://0.0.0.0:3223/?tls-chain=cert.pem&tls-key=key.pem
# MC_ADMIN_LISTEN_URI - grpc port for admin - use mc-admin-http-gw to interact.
#   default insecure-mca://127.0.0.1:8001/
# MC_NETWORK - path to network config file
#   default /config/network.toml
# MC_TOKENS - path to signed tokens config file
#   default /config/tokens.signed.json
# MC_LEDGER_PATH - directory for ledger database
#   default /ledger
# MC_SCP_DEBUG_DUMP - directory for debugging
#   default /scp-debug-dump
# MC_SEALED_BLOCK_SIGNING_KEY - file path for sealed signing key
#   default /sealed/block-signing-key

# Required Vars ledger-distribution
# MC_DEST - s3 path for publish ledger
#   example s3://mobilecoin.chain/node1.test.mobilecoin.com?region=eu-central-1

# AWS_ACCESS_KEY_ID - standard AWS vars
# AWS_SECRET_ACCESS_KEY - standard AWS vars
# AWS_REGION - standard AWS vars

# Optional Vars - Sentry Monitoring
# LEDGER_DISTRIBUTION_SENTRY_DSN - sentry DSN
# CONSENSUS_SERVICE_SENTRY_DSN - sentry DSN

# Optional Vars - Remote Logging
# ES_HOST
# ES_USERNAME
# ES_PASSWORD
# ES_PORT

set -e

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

echo "Starting Up with command ${1}"

# archive_curl <base url>
# Do HEAD to see if origin block exists
archive_curl()
{
    /usr/bin/curl -IfsSL --retry 3 "${1}00/00/00/00/00/00/00/0000000000000000.pb"
}

##############################################
# Optional, load env vars from .env file
DOTENV_CONFIG_FILE=${DOTENV_CONFIG_FILE:-"/config/.env"}
if [[ -f "${DOTENV_CONFIG_FILE}" ]]
then
    # Automatically export all loaded vars
    set -o allexport
    # shellcheck disable=SC1090 # optional import of .env
    source "${DOTENV_CONFIG_FILE}"
    set +o allexport
fi

######################################################################
# set up optional filebeat and bootstrap the ledger on normal start
if [[ "${1}" == "/usr/bin/supervisord" ]]
then
    # check for required vars
    is_set MC_BRANCH
    is_set MC_PEER_RESPONDER_ID
    is_set MC_CLIENT_RESPONDER_ID
    is_set MC_MSG_SIGNER_KEY
    is_set MC_IAS_API_KEY
    is_set MC_IAS_SPID
    is_set MC_DEST
    is_set AWS_ACCESS_KEY_ID
    is_set AWS_SECRET_ACCESS_KEY
    is_set AWS_REGION

    # Enable filebeat if provided with ElasticSearch target vars.
    if [[ -n "${ES_HOST}" ]]
    then
        echo "Found ES_HOST - enabling filebeat log shipping"
        # required vars for shipping logs via filebeat
        is_set ES_PASSWORD
        is_set ES_USERNAME

        export ES_PORT=${ES_PORT:-443}
        export ES_INDEX=${ES_INDEX:-"filebeat"}
        export MC_LOG_UDP_JSON=127.0.0.1:16666

        # enable logstash in supervisord
        sed -i -e 's/numprocs=0/numprocs=1/g' /etc/supervisor/conf.d/logstash.conf
    fi

    # Ledger
    echo "Bootstrapping ledger database"

    # Optional Vars
    # MC_TX_SOURCE_URL - http source to retrieve block data.

    # Default vars
    export MC_LEDGER_PATH=${MC_LEDGER_PATH:-"/ledger"}
    export MC_STATE_FILE=${MC_STATE_FILE:-"/ledger/.distribution-state"}
    export ORIGIN_LEDGER_PATH=${ORIGIN_LEDGER_PATH:-"/var/lib/mobilecoin/origin_data/data.mdb"}

    if [[ -f "${MC_LEDGER_PATH}/data.mdb" ]]
    then
        echo "Existing database found at ${MC_LEDGER_PATH}/data.mdb"
        echo "Migrating ledger to latest version"
        cp /ledger/data.mdb "/ledger/data.mdb.$(date +%y%m%d-%H%M%S)"
        /usr/bin/mc-ledger-migration --ledger-db "${MC_LEDGER_PATH}"
    else
        # Look for wallet keys seed - development and CD deploys
        if [[ -n "${INITIAL_KEYS_SEED}" ]]
        then
            echo "INITIAL_KEYS_SEED found - populating origin data"
            export INITIALIZE_LEDGER="true"

            /usr/local/bin/generate_origin_data.sh

            cp /tmp/sample_data/ledger/data.mdb "${MC_LEDGER_PATH}"

        # Try to find origin block from s3 archive - preserve existing data, testnet/mainnet
        elif archive_curl "${MC_TX_SOURCE_URL}"
        then
            echo "Remote archive ledger found - restore with ledger-from-archive"
            echo "  Note: RUST_LOG=warn so we don't get 1m+ lines of logs"
            echo "  Please be patient"

            RUST_LOG=warn /usr/bin/ledger-from-archive --ledger-db "${MC_LEDGER_PATH}"

        # Copy ledger from embedded origin block
        elif [[ -f "${ORIGIN_LEDGER_PATH}" ]]
        then
            echo "Found origin ledger at ${ORIGIN_LEDGER_PATH}"
            cp "${ORIGIN_LEDGER_PATH}" "${MC_LEDGER_PATH}"
        else
            # We ain't found nothin, bail out!
            echo "INITIAL_KEYS_SEED not set, no remote ledger and cannot find origin ledger file"
            exit 1
        fi
    fi
fi

# Run with docker command - probably /usr/bin/supervisord
exec "$@"
