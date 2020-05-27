### PizzaMOB Leaderboard

To run:

1. Start mobilecoind

    ```sh
    RUST_BACKTRACE=full RUST_LOG=trace,mc_watcher=error,mc_ledger_sync=error,mc_connection=error,hyper=error,reqwest=error,mio=error,rustls=error,want=error \
    SGX_MODE=HW IAS_MODE=PROD CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
    cargo run --release -p mc-mobilecoind -- \
    --peer mc://node1.test.mobilecoin.com:443/ \
    --peer mc://node2.test.mobilecoin.com:443/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.test.mobilecoin.com/ \
    --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.test.mobilecoin.com/ \
    --poll-interval 10 \
    --mobilecoind-db /tmp/testnet-transaction-db \
    --ledger-db /tmp/testnet-ledger-db \
    --service-port 4444
    ```

1. Start the leaderboard, default host:port on `localhost:5000`

    ```sh
    pip3 install -r requirements.txt
    ./compile_proto.sh
    python3 pizzamob_leaderboard.py --entropy 1234567812345678123456781234567812345678123456781234567812345678
    ```