#!/bin/bash

set -e

SCRIPT_DIR=$(dirname "$0")
cd $SCRIPT_DIR

MC_ROOT=$PWD/../..
MC_API=$MC_ROOT/api/proto
MCD_API=$MC_ROOT/mobilecoind/api/proto
CONSENSUS_API=$MC_ROOT/consensus/api/proto
MINT_AUDITOR_API=$MC_ROOT/mint-auditor/api/proto

pip3 install grpcio grpcio-tools

python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/external.proto
python3 -m grpc_tools.protoc -I$MC_API --python_out=. $MC_API/blockchain.proto
python3 -m grpc_tools.protoc -I$MCD_API -I$CONSENSUS_API -I$MC_API --python_out=. --grpc_python_out=. $MCD_API/mobilecoind_api.proto
python3 -m grpc_tools.protoc -I$MINT_AUDITOR_API --python_out=. --grpc_python_out=. $MINT_AUDITOR_API/mint_auditor.proto
