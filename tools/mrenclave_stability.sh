#!/bin/bash

# Copyright (c) 2018-2021 The MobileCoin Foundation
#
# This script is run from outside the container to exercise CI functionality, via
# mob.
#
# Invokes check, build, and test, forwarding any config options each time,
# such as `--release`,`--hw`, `--tag`
set -ex

# check if mrenclave changes after rebuilding

./mob clean
./mob build --locked "$@"

BUILD_DIR=$(./mob build-dir "$@")
FILE="$BUILD_DIR"/libconsensus-enclave.mrenclave

test -f "$FILE"
MRENCLAVE1=$(cat $FILE)

# Move the target directory so that we can do a diff comparison later if test fails
FIRST_BUILD=$(mktemp -d -t test-XXXXXXXXXX)
mkdir -p "$FIRST_BUILD"/enclave
mv target "$FIRST_BUILD"/
mv enclave/target "$FIRST_BUILD"/enclave/
ls -l $FIRST_BUILD/
ls -l $FIRST_BUILD/enclave/
ls -l $FIRST_BUILD/enclave/$BUILD_DIR

./mob build --locked "$@"

test -f "$FILE"
MRENCLAVE2=$(cat $FILE)

set +e

if [ "$MRENCLAVE1" != "$MRENCLAVE2" ] ; then
    echo "Warning: MRENCLAVE changed after rebuild!"
    diff -rq target "$FIRST_BUILD"/target
    diff -rq enclave/target "$FIRST_BUILD"/enclave/target
    exit 1
fi

ls -l $FIRST_BUILD/
ls -l $FIRST_BUILD/enclave/
ls -l $FIRST_BUILD/enclave/$BUILD_DIR

# Diff of rlibs that the enclave depends on.
# Making sure these don't change makes it much easier to triage bugs
# if the MRENCLAVE value starts changing.
#
# There are some known issues with mbedtls that we're ignoring for now, that
# also cause enclave.a to differ
#
#Step #2 - "mrenclave": Files enclave/target/debug/deps/libenclave-05b7c4d920a8171d.a and /tmp/test-i6qaDpf9S8/enclave/target/debug/deps/libenclave-05b7c4d920a8171d.a differ
#Step #2 - "mrenclave": Files enclave/target/debug/deps/libmbedtls-b16403e90f194a65.rlib and /tmp/test-i6qaDpf9S8/enclave/target/debug/deps/libmbedtls-b16403e90f194a65.rlib differ
diff -q -x "*.rmeta" -x "*.d" -x "*.so" -x "*mbedtls*" -x "libenclave-*.a" \
    enclave/$BUILD_DIR/deps \
    $FIRST_BUILD/enclave/$BUILD_DIR/deps

if [ "$?" != 0 ] ; then
    echo "Warning: unexpected rlib diff detected in enclave build!"
    exit 1
fi

rm -rf "$FIRST_BUILD"
