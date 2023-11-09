#!/bin/bash

set -ex

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

MC_ROOT=$PWD/../..
MC_API=$MC_ROOT/api/proto
MC_ATTEST_API=$MC_ROOT/attest/api/proto
MC_FOG_API=$MC_ROOT/fog/api/proto
MCD_API=$MC_ROOT/mobilecoind/api/proto
CONSENSUS_API=$MC_ROOT/consensus/api/proto

pip3 install grpcio grpcio-tools

python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/external.proto
python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/blockchain.proto
python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/quorum_set.proto
python3 -m grpc_tools.protoc -I$MC_API -I$MC_ATTEST_API --python_out=. $MC_ATTEST_API/attest.proto
python3 -m grpc_tools.protoc -I$MC_API -I$MC_ATTEST_API -I$MC_FOG_API --python_out=. $MC_FOG_API/fog_common.proto
python3 -m grpc_tools.protoc -I$MC_API -I$MC_ATTEST_API -I$MC_FOG_API --python_out=. $MC_FOG_API/ledger.proto
python3 -m grpc_tools.protoc -I$MC_API -I$CONSENSUS_API --python_out=. $CONSENSUS_API/consensus_common.proto
python3 -m grpc_tools.protoc -I$MCD_API -I$CONSENSUS_API -I$MC_API -I$MC_ATTEST_API -I$MC_FOG_API --python_out=. --grpc_python_out=. $MCD_API/mobilecoind_api.proto
