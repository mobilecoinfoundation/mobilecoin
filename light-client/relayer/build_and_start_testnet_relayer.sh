export SGX_MODE=HW
export IAS_MODE=PROD
export MC_LOG=info,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error

./tools/download_sigstruct.sh
export CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css
export MC_FOG_INGEST_ENCLAVE_CSS=$(pwd)/ingest-enclave.css

mkdir -p /tmp/testnet

cargo run --release -p mc-mobilecoind -- \
  --ledger-db ~/testnet/ledger-db \
  --watcher-db ~/testnet/watcher-db \
  --poll-interval 1 \
  --chain-id test \
  --peer mc://node1.test.mobilecoin.com/ \
  --peer mc://node2.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
  --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
