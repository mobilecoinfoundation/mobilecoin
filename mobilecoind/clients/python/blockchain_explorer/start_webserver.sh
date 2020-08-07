#!/bin/sh

# setup mob_client
cd ../mob_client
pip3 install -r requirements.txt
./compile_proto.sh

cd ../blockchain_explorer

# install mobilecoind
if [ ! -d "./mobilecoin-testnet-linux" ]
  then
    echo "Installing mobilecoind binary."
    curl -L https://github.com/mobilecoinofficial/mobilecoin/releases/latest/download/mobilecoin-testnet-linux.tar.gz --output latest.tar.gz
    tar -zxvf ./latest.tar.gz
    rm ./latest.tar.gz
fi

# kill old mobilecoind processes
ps -ef | grep mobilecoind | grep -v grep | awk '{print $2}' | xargs kill

# run mobilecoind
./mobilecoin-testnet-linux/bin/mobilecoind \
        --ledger-db /tmp/ledger-db \
        --poll-interval 10 \
        --peer mc://node1.test.mobilecoin.com/ \
        --peer mc://node2.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
        --mobilecoind-db /tmp/transaction-db \
        --listen-uri insecure-mobilecoind://0.0.0.0:4444/ \
        --watcher-db /tmp/watcher-db &

# run the blockchain explorer flask site
pip3 install -r requirements.txt
python3 ./blockchain_explorer.py
