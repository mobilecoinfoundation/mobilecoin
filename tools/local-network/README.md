## Intro

This directory contains scripts for running a local mobilecoin consensus network and a `mobilecoind` instance.
The enclaves are built in pre-release mode, which provides debug symbols for debugging purposes, so it is only intended to be used for development and testing purposes.

To run a local network, you may provide both the `IAS_API_KEY` and `IAS_SPID`, which you can obtain by registering with the [Intel SGX Portal](https://api.portal.trustedservices.intel.com/EPID-attestation)
These are optional, and the script will provide defaults that work for local testing in software mode.

## Quickstart

The following sequence is a basic way to start a network locally.

```
$ export MC_LOG=info
$ export LEDGER_BASE=$PWD/target/sample_data/ledger
$ ./tools/local-network/bootstrap.sh
$ ./tools/local-network/local_network.py --network-type dense5 &
```

Both `bootstrap.sh` and `local_network.py` will use cargo to build the required binaries.
You only have to bootstrap once. To take down the network and start up a fresh one,
kill the `local_network.py` and restart it.

Stopping the network does not generally wipe out the ledger it generated.
If you want to also start from a clean ledger, the script's "work directory" is (typically) `target/release/mc-local-network`,
delete this in order to start the ledger over from scratch the next time you start the network.

## bootstrap.sh

Each node in the network requires a ledger containing at least one block to start. Further, to perform transactions on the network you will
need private master keys.

This is a simple script to bootstrap a test ledger and keys to play with. The script writes the keys to `target/sample_data/keys` and the ledger to `target_sample_data/ledger`.

## local_network.py

This script starts a local mobilecoin consensus network by launching a separate process for each consensus validator and configuring them to communicate via a default set of ports. It takes the following parameters:

- (required) `--network-type` - describes the network topology, one of `dense5`, `a-b-c`, `ring5` or `ring5b`
- (optional) `--skip-build` - does not rebuild consensus node binaries

It relies on environment variables for configuration:

- (required) `LEDGER_BASE` - Points at the ledger directory to initialize the nodes with (e.g. `./target/sample_data/ledger`).
- (optional) `IAS_API_KEY` - IAS Api key.
- (optional) `IAS_SPID` - IAS Service Provider ID.
- (optional) `MC_LOG` - Log level configuration.
- (optional) `MOB_RELEASE` - When set to 1 (default), build in release mode.
- (optional) `LOG_BRANCH` - Enable cloud logging, tagging all logs/metrics with the provided branch name.
- (optional) `LOGSTASH_HOST` - Logstash host:port to send logs to.
- (optional) `GRAFANA_PASSWORD` - Grafana API key to sent metrics to.

## mobilecoind.sh

This script starts mobilecoind and connects it to the nodes started by `local_network.py`.

It has sane defaults and requires no extra configuration.

Note that, current versions of `local_network.py` already start a `mobilecoind`, so you may
be able to use that one instead of starting an additional instance.

## send-mobilecoind-txs.sh

This script uses curl to ask the `mobilecoind` started in the local network to send some transactions, to drive the network.

Note that you must separately start `mobilecoind-json` for this script to work.
