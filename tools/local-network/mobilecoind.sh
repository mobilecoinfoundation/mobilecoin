#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation

set -e
trap 'pkill -P $$' SIGINT SIGTERM

if [ "$MOB_RELEASE" = "0" ]; then
    CARGO_FLAGS=""
    TARGET_DIR="target/debug"
else
    CARGO_FLAGS="--release"
    TARGET_DIR="target/release"
fi

if [[ -z "$MC_LOG" ]]; then
    export MC_LOG="info,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error"
fi

# Change to the project's root directory
cd $(dirname "$0")/../..

WORK_DIR="/tmp/mc-local-network"
mkdir -p $WORK_DIR

# The hostname the nodes are running on
NODES_HOST="${NODES_HOST:-localhost}"

# URL to sync ledger from
LEDGER_SYNC_URL=${LEDGER_SYNC_URL:-file:///tmp/mc-local-network/node-ledger-distribution-1}

# Run mobilecoind
echo "Nodes host:      $NODES_HOST"
echo "Ledger sync url: $LEDGER_SYNC_URL"

rm -rf $WORK_DIR/mobilecoind-ledger-db $WORK_DIR/mobilecoind-tx-db

cargo run -p mc-mobilecoind $CARGO_FLAGS -- \
    --ledger-db $WORK_DIR/mobilecoind-ledger-db \
    --watcher-db $WORK_DIR/watcher-db \
    --poll-interval 1 \
    --peer insecure-mc://$NODES_HOST:3223/ \
    --peer insecure-mc://$NODES_HOST:3233/ \
    --tx-source-url "$LEDGER_SYNC_URL" \
    --mobilecoind-db $WORK_DIR/mobilecoind-tx-db \
    --insecure-mobilecoind://0.0.0.0:4444/
