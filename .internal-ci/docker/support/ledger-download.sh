#!/bin/bash

data="${1}"

if [[ -n "${MC_LEDGER_DB_URL}" ]]
then
    echo "MC_LEDGER_DB_URL set, restoring ${data}/ledger/data.mdb from backup"
    if [[ -f "${data}/ledger/data.mdb" ]]
    then
        echo "Found existing ledger database, skipping download"
    else
        echo "Downloading ledger data.mdb"
        mkdir -p "${data}/tmp-ledger"
        curl -L "${MC_LEDGER_DB_URL}" -o "${data}/tmp-ledger/data.mdb"
        mkdir -p "${data}/ledger"
        mv "${data}/tmp-ledger/data.mdb" "${data}/ledger/data.mdb"
    fi
fi

if [[ -n "${MC_WATCHER_DB_URL}" ]]
then
    echo "MC_WATCHER_DB_URL set, restoring ${data}/watcher/data.mdb from backup"
    if [[ -f "${data}/watcher/data.mdb" ]]
    then
        echo "Found existing watcher database, skipping download"
    else
        echo "Downloading watcher data.mdb"
        mkdir -p "${data}/tmp-watcher"
        curl -L "${MC_WATCHER_DB_URL}" -o "${data}/tmp-watcher/data.mdb"
        mkdir -p "${data}/watcher"
        mv "${data}/tmp-watcher/data.mdb" "${data}/watcher/data.mdb"
    fi
fi
