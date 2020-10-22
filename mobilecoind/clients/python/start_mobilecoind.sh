#!/bin/sh

# location to store mobilecoind binary and databases
TMP_DIR=/tmp/mobilecoind-testnet
RELEASE_URL=mobilecoind-mirror-tls # or `mobilecoin-testnet-linux`
RELEASE_DIR=mobilecoind-mirror # or `mobilecoin-testnet-linux`

# optionally delete old data with "--clean"
while test $# -gt 0
do
  case "$1" in
    --clean)
      echo "Removing old databases."
      rm -rf $TMP_DIR
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

# kill old mobilecoind processes
mobilecoind_processes=$(ps -ef | grep mobilecoind | grep -v grep | grep -v start_mobilecoind) #no spaces!
if [ ! -z "$mobilecoind_processes" -a "$mobilecoind_processes" != " " ];
  then
    echo "Killing old mobilecoind processes."
    ps -ef | grep mobilecoind | grep -v grep | grep -v start_mobilecoind | awk '{print $2}' | xargs kill
fi

# install mobilecoind from the current TestNet release
echo "Installing mobilecoind from latest $RELEASE_URL..."
rm -rf $TMP_DIR/$RELEASE_DIR
curl -L https://github.com/mobilecoinfoundation/mobilecoin/releases/latest/download/$RELEASE_URL.tar.gz --output latest.tar.gz
tar -zxvf ./latest.tar.gz
rm ./latest.tar.gz
mv ./$RELEASE_DIR $TMP_DIR

export RUST_LOG=debug

# run mobilecoind
# we are leaving the log file in the project directory rather than moving it to TMP_DIR on purpose
echo "Starting mobilecoind"
$TMP_DIR/bin/mobilecoind \
  --ledger-db $TMP_DIR/ledger-db \
  --poll-interval 2 \
  --peer mc://node1.test.mobilecoin.com/ \
  --peer mc://node2.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
  --mobilecoind-db $TMP_DIR/transaction-db \
  --listen-uri insecure-mobilecoind://127.0.0.1:4444/ \
  --watcher-db $TMP_DIR/watcher-db 2>&1 > mobilecoind.log &
