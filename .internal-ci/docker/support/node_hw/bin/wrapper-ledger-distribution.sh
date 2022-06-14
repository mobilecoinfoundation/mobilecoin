#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# wrapper-ledger-distribution.sh - Wrapper script around ledger-distribution to
# solve last/next and missing state logic.

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
export MC_STATE_FILE=${MC_STATE_FILE:-"/ledger/.distribution-state"}
export MC_SENTRY_DSN=${LEDGER_DISTRIBUTION_SENTRY_DSN}

if [[ -f "/ledger/.distribution-state" ]]
then
    export MC_START_FROM=last
else
    export MC_START_FROM=next
fi

/usr/bin/ledger-distribution
