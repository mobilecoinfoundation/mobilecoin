#!/bin/bash

set -ex

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

MC_ROOT=$PWD/../..
MC_API=$MC_ROOT/api/proto
MCD_API=$MC_ROOT/mobilecoind/api/proto
CONSENSUS_API=$MC_ROOT/consensus/api/proto

pip3 install grpcio grpcio-tools

python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/external.proto
python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/blockchain.proto
python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/quorum_set.proto
python3 -m grpc_tools.protoc -I$MC_API -I$CONSENSUS_API --python_out=. $CONSENSUS_API/consensus_common.proto
python3 -m grpc_tools.protoc -I$MCD_API -I$CONSENSUS_API -I$MC_API --python_out=. --grpc_python_out=. $MCD_API/mobilecoind_api.proto
