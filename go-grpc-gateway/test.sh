#!/bin/bash
#
# Test:
# Create a rust stub server, and a go-grpc-gateway which points to it.
# Then try to talk to rust stub server via the gateway, using curl.

set -e

if [ ! -f "go-grpc-gateway" ]; then
    echo "Missing go-grpc-gateway, needs go build"
    exit 1
fi

: "${CARGO_TARGET_DIR:=../target/}"

if [ ! -f "$CARGO_TARGET_DIR/debug/stub" ]; then
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
"$CARGO_TARGET_DIR/debug/stub" --chain-id "local" --client-listen-uri insecure-fog://localhost:3000 &
pid=$!

sleep 1

# Spawn grpc proxy
./go-grpc-gateway -grpc-insecure -grpc-server-endpoint localhost:3000 -http-server-listen :8080 -logtostderr &
pid2=$!

sleep 5

result=$(curl -XPOST -H "Content-Type: application/json" http://localhost:8080/report.ReportAPI/GetReports -d "{}")
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

result=$(curl -XPOST -H "Content-Type: application/x-protobuf" http://localhost:8080/report.ReportAPI/GetReports -d "")
expected=$(echo -e "\\032\\004\\001\\001")
if [ "$result" != "$expected" ]; then
    set +x
    echo "Unexpected result for ReportAPI/GetReports"
    echo "$result"
    echo "Expected:"
    echo "$expected"
    exit 1
fi

# Test if Chain-Id is being properly passed on
result=$(curl -XPOST -H "Content-Type: application/x-protobuf" -H "Chain-Id: local" http://localhost:8080/report.ReportAPI/GetReports -d "")
expected=$(echo -e "\\032\\004\\001\\001")
if [ "$result" != "$expected" ]; then
    set +x
    echo "Unexpected result for ReportAPI/GetReports with Chain-Id: local"
    echo "$result"
    echo "Expected:"
    echo "$expected"
    exit 1
fi

# Test the same as above (with chain id header) and check that we get a 200 status response
result=$(curl -o /dev/null -w "%{http_code}" -XPOST -H "Content-Type: application/x-protobuf" -H "Chain-Id: local" http://localhost:8080/report.ReportAPI/GetReports -d "")
expected="200"
if [ "$result" != "$expected" ]; then
    echo "Bad status with Chain-Id: local"
    echo "$result"
    exit 1
fi

# Test if an error is being propagated when Chain-Id is wrong
result=$(curl -o /dev/null -w "%{http_code}" -XPOST -H "Content-Type: application/x-protobuf" -H "Chain-Id: wrong" http://localhost:8080/report.ReportAPI/GetReports -d "")
expected="400"
if [ "$result" != "$expected" ]; then
    echo "Passed, but we expected failure for ReportAPI/GetReports with Chain-Id: wrong"
    echo "$result"
    exit 1
fi

set +x
echo "Success!"
