Fog Distribution
================

This utility is a minor variation on the slam script, adding the ability to send to fog users.  Its purpose is to distribute coins to fog users from the genesis block, mostly for testing.

As with the slam script, you must have a local copy of the ledger and a set of keys to use as the source accounts.  This utility also requires a set of fog-enabled accounts which will be the destination to send the coins.  So the sample data directory should have a ```fog_keys``` subdir in addition to slam's ```keys``` and ```ledger``` subdirs.  When creating ```fog_keys```, be sure to pass both the ```--fog-report-url``` option with the desired Fog URL, and also the ```--seed``` option do make sure the fog account keys are different from the regular keys:

```
    cd target/sample_data

    rm -rf fog_keys keys ledger; mkdir -p fog_keys keys ledger

    cargo run --release --manifest-path=../mobilecoin/Cargo.toml -p mc-util-keyfile --bin sample-keys -- --num 100 --output-dir ./fog_keys --fog-authority-root ca.crt --fog-report-url fog-report.NETWORK.mobilecoin.com --seed 1234567812345678123456781234567812345678123456781234567812345678

    cargo run --release --manifest-path=../mobilecoin/Cargo.toml -p mc-util-keyfile --bin sample-keys -- --num 100 --output-dir ./keys

    cargo run --release --manifest-path=../mobilecoin/Cargo.toml -p generate-sample-ledger -- --txs 100
```

There are two modes of running this utility:

* against deployed consensus nodes
* against local consensus node(s)

Either way, both the utility and the consensus nodes must use the same ledger.

Running against deployed
=====

To run against a deployed network, you need to provide which nodes to submit transactions to. You may also need to provide the tombstone block offset if the deployed network has already progressed to a higher block.

To match the deployed network's ledger, you currently need 1000 source accounts and 100 transactions per account.  You can verify the current deployed ledger parameters by checking ```deploy/02-initial-node-data.yaml```.

```
    cd target/sample_data

    # generate as many destination keys as you like, as per above

    cargo run --release --manifest-path=../mobilecoin/Cargo.toml -p mc-util-keyfile --bin sample-keys -- --num 1000 --output-dir ./keys

    cargo run --release --manifest-path=../mobilecoin/Cargo.toml -p generate-sample-ledger -- --txs 100

    cd ../..

    cargo run -p fog-distribution --release -- --sample-data-dir target/sample_data/ \
        --peer mc://node1.NETWORK.mobilecoin.com:443 \
        --peer mc://node2.NETWORK.mobilecoin.com:443 \
        --peer mc://node3.NETWORK.mobilecoin.com:443 \
        --peer mc://node4.NETWORK.mobilecoin.com:443 \
        --peer mc://node5.NETWORK.mobilecoin.com:443 \
        --tombstone-block 130
```

Running against local
=====

If you are running a consensus network locally, you will replace the urls above with either:

    * `mc://localhost:3223` if running outside Docker, with the port matching the local ports corresponding to the consensus nodes.

    * `mc://<container_name>:3223` if running inside Docker, making sure that the ports are published on the docker container

### Inside Docker

If you are running inside docker, also make sure that you have set up the containers to share the docker network bridge.

Please see the local-services [README](../../local-services/README.md) for more information.

Increasing Transaction Count (with generate-sample-ledger)
=====

NOTE: If you are running against a deployed network, you *must* use the deployed network's ledger.  You can change the deployed ledger by editing ```deploy/02-initial-node-data.yaml``` and redeploying.

This script relies on the existence of a ledger with valid bootstrapped transactions. The easiest way to make more transactions is to bootstrap a bigger ledger. To bootstrap the ledger, please do the following:

The sample-keys binary will create keys from which to seed transactions. By convention, we tend to create the bootstrapped keys and ledger in the target/sample_data dir for local development, as that is also where the deployment bootstraps the keys.

```
    mkdir -p target/sample_data/keys target/sample_data/ledger
    cd target/sample_data && cargo run --manifest-path=../mobilecoin/Cargo.toml -p mc-util-keyfile --bin sample-keys -- --num 1000
```

The generate-sample-ledger binary will use the keys and the num you provide here will result in that number of utxos per key.

```
    cd target/sample_data/ && cargo run --manifest-path=../mobilecoin/Cargo.toml -p generate-sample-ledger -- --txs 100
```

Using the Deployed Ledger (without running generate-sample-ledger)
=====

You can use the ledger from a deployed network to run against, without having to run generate-sample-ledger locally. Depending on the size of the ledger, this can be a huge time savings.

```
    docker pull mobilecoin/node_hw:NETWORK-latest
    docker run -it --detach=true --entrypoint="/bin/bash" --name=extract_ledger mobilecoin/node_hw:NETWORK-latest
    docker cp extract_ledger:/var/lib/mobilecoin/ledger/ /tmp/ledger
```
