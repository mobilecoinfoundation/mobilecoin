#!/bin/bash
#
# Copyright (c) 2018-2021 The MobileCoin Foundation
#
# Test for mrenclave stability
# Meant to be run as a git bisect run script, inside the prompt
# This may be a lot faster if there are docker image changes in recent history

set -ex

cd public

FILE=target/debug/libconsensus-enclave.mrenclave

cargo clean && (cd enclave && cargo clean)
cargo build -p mc-consensus-service --locked
test -f $FILE
MRENCLAVE1=$(cat $FILE)

cargo clean && (cd enclave && cargo clean)
cargo build -p mc-consensus-service --locked
test -f $FILE
MRENCLAVE2=$(cat $FILE)

if [ "$MRENCLAVE1" != "$MRENCLAVE2" ] ; then
    echo "Warning: MRENCLAVE changed after rebuild!"
    exit 1
fi
