#!/bin/sh

# location to store mobilecoind binary and databases
TMP_DIR=/tmp/mobilecoind-testnet

# optionally delete old data with "--clean"
while test $# -gt 0
do
  case "$1" in
    --clean)
      echo "Removing old databases."
      rm -rf $TMP_DIR/ledger-db
      rm -rf $TMP_DIR/transaction-db
      rm -rf $TMP_DIR/watcher-db
      rm -rf $TMP_DIR/mobilecoin-testnet-linux
      ;;
    --*)
      echo "bad option $1"
      ;;
    *)
      echo "bad argument $1"
      ;;
  esac
  shift
done

# install mobilecoind from the current TestNet release
echo "Downloading mobilecoind from releases..."
if [ ! -d "$TMP_DIR/mobilecoin-testnet-linux" ]
  then
    echo "Installing mobilecoind binary."
    curl -L https://github.com/mobilecoinofficial/mobilecoin/releases/latest/download/mobilecoin-testnet-linux.tar.gz --output latest.tar.gz
    tar -zxvf ./latest.tar.gz
    rm ./latest.tar.gz
    mv ./mobilecoin-testnet-linux $TMP_DIR
fi

# kill old mobilecoind processes
mobilecoind_processes=$(ps -ef | grep mobilecoind | grep -v grep | grep -v start_mobilecoind) #no spaces!
if [ ! -z "$mobilecoind_processes" -a "$mobilecoind_processes" != " " ];
  then
    echo "Killing old mobilecoind processes."
    ps -ef | grep mobilecoind | grep -v grep | grep -v start_mobilecoind | awk '{print $2}' | xargs kill
fi

export RUST_LOG=debug

# run mobilecoind
echo "Starting mobilecoind"
$TMP_DIR/mobilecoin-testnet-linux/bin/mobilecoind \
  --ledger-db $TMP_DIR/ledger-db \
  --poll-interval 2 \
  --peer mc://node1.test.mobilecoin.com/ \
  --peer mc://node2.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
  --mobilecoind-db $TMP_DIR/transaction-db \
  --listen-uri insecure-mobilecoind://127.0.0.1:4444/ \
  --watcher-db $TMP_DIR/watcher-db 2>&1 > mobilecoind.log &
