#!/bin/sh

set -ex

export GO111MODULES=on

# Compile proto files
INC="-I ../fog/api/proto -I ../api/proto -I ../fog/report/api/proto -I ../attest/api/proto -I ../consensus/api/proto"

mkdir -p docs gen

for proto_file in blockchain external quorum_set consensus_client consensus_config consensus_common fog_common ledger view report kex_rng attest; do
    protoc $INC --grpc-gateway_out ./gen \
         --go_out ./gen --go_opt paths=source_relative \
         --go-grpc_out ./gen --go-grpc_opt paths=source_relative \
         --grpc-gateway_opt logtostderr=true \
         --grpc-gateway_opt paths=source_relative \
         --grpc-gateway_opt generate_unbound_methods=true \
         --descriptor_set_out=./gen/$proto_file.pb \
         $proto_file.proto

    protoc $INC --openapiv2_out ./docs --openapiv2_opt logtostderr=true $proto_file.proto
done

# Compile the go program, using mod=readonly
# If the mod file needs to updated, just type `go build` instead.
go build -mod=readonly
