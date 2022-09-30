#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# wrapper-ledger-distribution.sh - Wrapper script around ledger-distribution to
# solve last/next and missing state logic.

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

archive_curl()
{
    /usr/bin/curl -IfsSL --retry 3 "${1}00/00/00/00/00/00/00/0000000000000000.pb" -o /dev/null
}

is_set MC_DEST
is_set AWS_ACCESS_KEY_ID
is_set AWS_SECRET_ACCESS_KEY
is_set AWS_REGION
is_set MC_BRANCH

# Optional - for sentry monitoring
# LEDGER_DISTRIBUTION_SENTRY_DSN
# MC_LOG_UDP_JSON

# Default vars
export MC_LEDGER_PATH=${MC_LEDGER_PATH:-"/ledger"}
export MC_STATE_FILE=${MC_STATE_FILE:-"${MC_LEDGER_PATH}/.distribution-state"}
export MC_SENTRY_DSN=${LEDGER_DISTRIBUTION_SENTRY_DSN}

if [[ -f "${MC_STATE_FILE}" ]]
then
    # Check for valid state file
    echo "mc.app:wrapper-ledger-distribution - State file found MC_START_FROM=last"
    echo "mc.app:wrapper-ledger-distribution - Check for valid next_block"

    next_block=$(jq -r .next_block "${MC_STATE_FILE}")
    if [[ "${next_block}" -le 0 ]]
    then
        echo "mc.app:wrapper-ledger-distribution - Invalid next_block <= 0"
        exit 1
    fi

    export MC_START_FROM=last
else
    echo "mc.app:wrapper-ledger-distribution - no state file found."
    echo "mc.app:wrapper-ledger-distribution - checking for an existing block 0 in s3"

    if archive_curl "${MC_TX_SOURCE_URL}"
    then
        echo "mc.app:wrapper-ledger-distribution - block 0 found in s3 MC_START_FROM=next"
        export MC_START_FROM=next
    else
        echo "mc.app:wrapper-ledger-distribution - no s3 archive found MC_START_FROM=zero"
        export MC_START_FROM=zero
    fi
fi

/usr/bin/ledger-distribution
