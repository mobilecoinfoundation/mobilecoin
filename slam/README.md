# Slam Load Testing

Slam is a load testing tool that rapidly submits transactions to a consensus network.

Slam testing a consensus network usually involves:

1. Obtaining a copy of the initial ledger content and corresponding private keys.
1. Running Slam.
1. Monitoring the network's performance.

# Obtaining an initial ledger and keys

In order to create transactions, Slam requires a copy of the ledger and the set of private keys that own the contents of the ledger. The ledger and keys must **exactly** match those used by the consensus network; if not, Slam's transactions will likely be rejected with `InvalidTxOutMembershipProof` or `LedgerDbError`.

## Generating a local ledger and keys
If you know how the consensus network's ledger was initialized, you can initialize the same ledger locally with:

```
    mobilecoin $ mkdir -p target/sample_data
    mobilecoin $ cd sample_data
    mobilecoin/target/sample_data $ cargo run -p mc-util-keyfile --bin sample-keys --release -- --num 1000

    mobilecoin/target/sample_data $ cargo run -p mc-util-generate-sample-ledger --bin generate-sample-ledger --release -- --num 100
```


## Using a deployed ledger
Alternatively, Slam can use the ledger from a deployed network instead of a locally-generated one:

```
    docker pull mobilecoin/node_hw:master-latest
    docker run -it --detach=true --entrypoint="/bin/bash" --name=extract_ledger mobilecoin/node_hw:master-latest
    docker cp extract_ledger:/var/lib/mobilecoin/ledger/ /tmp/ledger
```

# Running Slam

To Run Slam against a deployed network (e.g. "other"), set one of the following environment variables. If you get them wrong, you'll probably see "Attestation failure" messages.

```
# aws s3 cp s3://enclave-distribution.other.mobilecoin.com/consensus/consensus-enclave.css ./s
export CONSENSUS_ENCLAVE_CSS=/home/you/consensus-enclave.css

# Local development
export CONSENSUS_ENCLAVE_PRIVKEY=/home/you/Enclave_private.pem
```

Then, run slam in `release` mode:

```
    cargo run -p mc-slam --release -- --sample-data-dir target/sample_data/ \
        --peer mc://node1.demo.mobilecoin.com \
        --peer mc://node2.demo.mobilecoin.com \
        --peer mc://node3.demo.mobilecoin.com \
        --peer mc://node4.demo.mobilecoin.com \
        --peer mc://node5.demo.mobilecoin.com \
        --add-tx-delay-ms 500 \
        --tombstone-block 100 \
        --with-ledger-sync \
        --tx-source-url https://s3-us-west-1.amazonaws.com/mobilecoin.chain/node1.demo.mobilecoin.com/
```

## Running Slam with a local consensus network

If you are running a consensus network locally, you will replace the peer URIs above with either:

* `insecure-mc://localhost:3223` if running outside Docker, with the port matching the local ports corresponding to the consensus nodes.
* `insecure-mc://<container_name>:3223` if running inside Docker, making sure that the ports are published on the docker container
