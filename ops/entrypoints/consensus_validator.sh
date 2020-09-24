#!/bin/bash
#
# This script will start the aesm_service daemon, if the isgx device node is
# present in /dev, then run consensus service with any given arguments.
#
# NOTE: Some of the environment variables are set in the Docker container, and
#       some are set in the docker run command

# exit if anything fails.
set -e

function launch() {
  app=$(basename $1)
  (set +e; while true; do
    echo "${@}"
    if [ -z "${NODE_LOG_DIR}" ]; then
       ${@}
    else
       ${@} >> ${NODE_LOG_DIR}/${app}.log 2>&1
    fi
    echo "${app} died; restarting after 10 seconds" >&2
    sleep 10
  done) &
}

if [ ! -z "${NODE_LOG_DIR}" ]; then
  mkdir -p ${NODE_LOG_DIR}
fi

if [ -c /dev/isgx ]; then
  # Use a subshell to prevent environment leakage
  (
    export AESM_PATH=/opt/intel/sgx-aesm-service/aesm
    export LD_LIBRARY_PATH=${AESM_PATH}

    ${AESM_PATH}/linksgx.sh
    /bin/mkdir -p /var/run/aesmd/
    /bin/chown -R aesmd:aesmd /var/run/aesmd/
    /bin/chmod 0755 /var/run/aesmd/
    /bin/chown -R aesmd:aesmd /var/opt/aesmd/
    launch ${AESM_PATH}/aesm_service --no-daemon
  )

  sleep 1
fi

# If the ledgerdir is not already populated, copy the origin block.
if [ ! -r "${NODE_LEDGER_DIR}/data.mdb" ]; then
    mkdir -p "${NODE_LEDGER_DIR}"
    rsync -a /var/lib/mobilecoin/origin_data/* ${NODE_LEDGER_DIR}/
fi

# Update the ledger to the current version if necessary
/usr/bin/mc-ledger-migration --ledger-db ${NODE_LEDGER_DIR}

if [[ -z "${AWS_PATH}" ]] || [[ -z "${AWS_SECRET_ACCESS_KEY}" ]] || [[ -z "${AWS_ACCESS_KEY_ID}" ]]; then
  echo "Warning: Must provide AWS_PATH, AWS_SECRET_ACCESS_KEY, and AWS_ACCESS_KEY_ID to start ledger distribution";
else
  launch /usr/bin/ledger-distribution \
    --ledger-path "${NODE_LEDGER_DIR}" \
    --dest "${AWS_PATH}"
fi

# Clean old dump directory - consensus writes a new dir, which is owned by root due to docker volume ownership
rm -rf /scp-debug-dump/${LOCAL_NODE_ID}

launch /usr/bin/mc-admin-http-gateway --listen-host 0.0.0.0 --listen-port ${NODE_MANAGEMENT_PORT} --admin-uri insecure-mca://127.0.0.1:9091/

exec consensus-service $@
