#!/bin/bash
#
# Test:
# Create a rust stub server, and a go-grpc-gateway which points to it.
# Then try to talk to rust stub server via the gateway, using curl.

set -e

if [ ! -f "grpc-proxy" ]; then
    echo "Missing grpc-proxy, needs go build"
    exit 1
fi

if [ ! -f "../target/debug/stub" ]; then
    echo "Missing rust testing stub, needs cargo build"
    exit 1
fi

my_exit() {
    set +x
    [ "$pid" ] && kill "$pid" || true
    [ "$pid2" ] && kill "$pid2" || true
}
trap my_exit EXIT INT HUP TERM

set -x

# Spawn rust stub server
./../target/debug/stub --client-listen-uri insecure-fog://localhost:3000 &
pid=$!

sleep 1

# Spawn grpc proxy
./grpc-proxy -grpc-insecure -grpc-server-endpoint localhost:3000 -http-server-listen :80 -logtostderr &
pid2=$!

sleep 5

result=$(curl -XPOST -H "Content-Type: application/json" http://localhost/report.ReportAPI/GetReports -d "{}")
expected="{\"reports\":[],\"chain\":[],\"signature\":\"AAEAAQ==\"}"

normalized_result=$(echo "$result" | jq -c .)
if [ "$normalized_result" != "$expected" ]; then
    set +x
    echo "Unexpected result for ReportAPI/GetReports"
    echo "$result"
    echo "Expected:"
    echo "$expected"
    exit 1
fi

result=$(curl -XPOST -H "Content-Type: application/x-protobuf" http://localhost/report.ReportAPI/GetReports -d "")
expected=$(echo -e "\\032\\004\\001\\001")
if [ "$result" != "$expected" ]; then
    set +x
    echo "Unexpected result for ReportAPI/GetReports"
    echo "$result"
    echo "Expected:"
    echo "$expected"
    exit 1
fi

set +x
echo "Success!"
