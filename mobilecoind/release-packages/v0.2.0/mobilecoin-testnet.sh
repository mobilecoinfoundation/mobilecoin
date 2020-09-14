#!/bin/bash
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT
export RUST_LOG=INFO

./bin/mobilecoind --ledger-db /tmp/mobilecoin/0.2.0/ledger \
      --poll-interval 1 \
      --peer mc://node1.test.mobilecoin.com/ \
      --peer mc://node2.test.mobilecoin.com/ \
      --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
      --mobilecoind-db /tmp/mobilecoin/0.2.0/wallet \
      --listen-uri insecure-mobilecoind://127.0.0.1:4444/ > /tmp/mobilecoind.log 2>&1 &
echo Daemon is starting up
sleep 5

./bin/mc-testnet-client
