## MobileCoin CLI client for use with `mobilecoind`

This code demonstrates a text-based client implementation in Python, that uses `mobilecoind` to interact with the MobileCoin network.

### Python client setup

To install required packages for the example client:

(from `mobilecoinofficial/mobilecoin/public/examples/python`)
```
pip3 install -r ./requirements.txt
```

To generate the pb2 files from the protocol buffers:
```
./compile_proto.sh
```

### Running the client

To run the MobileCoin client:
```
py ./main.py <host>:<port>
```

This document describes how to start a local `mobilecoind` instance below, for use with the command:
```
py ./main.py localhost:4444
```

If you do not want to run a local instance, there is a hosted instance of `mobilecoind` available online connected to a preproduction network:
```
py ./main.py --ssl mobilecoind.master.mobilecoin.com:443
```

### Client interaction

There is a file containing accounts that control funds in the preproduction MobileCoin network provided in `accounts.json`.

An example session:
```
$ ./main.py localhost:4444
# load accounts.json
Loaded 13 accounts.
# monitor alice [0]
Added a monitor for "alice" @ subaddress [0]
# monitor carol [0,1,2]
Added a monitor for "carol" @ subaddress [0,1,2]
# balance alice/0
alice/0 has 5000000000000000 pMOB @ block 12
# transfer 10000 alice/0 carol/1
Transfer initiated.
# status
Transaction not found.
# status
Transaction not found.
# status
Transaction verified.
# balance alice/0
alice/0 has 4999999999990000 pMOB @ block 14
# balance carol/1
carol/1 has 10000 pMOB @ block 15
# balance carol/0
carol/1 has 5000000000000000 pMOB @ block 16
```

### Running a local instance of `mobilecoind`

For security, users should prefer connecting to a local `mobilecoind` instance. This can be run using `cargo` with some variation of:

(from `mobilecoinofficial/mobilecoin`)
```
cargo run --bin `mobilecoind` -- \
   --ledger-db /tmp/ledger-db \
   --ledger-db-bootstrap target/sample_data/dev/ledger \
   --poll-interval 10 \
   --client-port 4444 \
   --peer mc://node1.dev.mobilecoin.com/ \
   --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.dev.mobilecoin.com/ \
   --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node2.dev.mobilecoin.com/ \
   --db /tmp/transaction_db \
   --service-port 4444
```

This command will launch a local `mobilecoind` instance that syncs the ledger from two nodes in the dev network and hosts the wallet service running on port 4444.

Note that it may be necessary to delete the previous transaction database for a clean run:

```
rm -rf /tmp/ledger-db; rm -rf /tmp/transaction_db; mkdir /tmp/transaction_db
```
