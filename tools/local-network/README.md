## Intro

This directory contains shell scripts for running a local 5-node mesh network and a `mobilecoind` instance.

## bootstrap.sh

This is a simple script to bootstrap a test ledger and keys to play with. The script writes the keys to `target/sample_data/keys` and the ledger to `target_sample_data/ledger`.

## local-network-5.sh

This script starts a 5 node network configured in a mesh topology. It relies on environment variables for configuration:

- (required) `LEDGER_BASE` - Points at the ledger directory to initialize the nodes with (e.g. `./target/sample_data/ledger`).
- (required) `IAS_API_KEY` - IAS Api key.
- (required) `IAS_SPID` - IAS Service Provider ID.
- (optional) `MC_LOG` - Log level configuration.
- (optional) `CLIENT_RESPONDER_HOST` - Override the default client responder hostname (defaults to localhost).
- (optional) `MOB_RELEASE` - When set to 1, build in release mode.
- (optional) `LOG_BRANCH` - Enable cloud logging, tagging all logs/metrics with the provided branch name.
- (optional) `LOGSTASH_HOST` - Logstash host:port to send logs to.
- (optional) `GRAFANA_PASSWORD` - Grafana API key to sent metrics to.
- (optional) `LEDGER_SYNC_S3` - Setting this to a path (`bucket/dir`) would configure `ledger-distribution` to store blocks on S3 instead of the local drive.

## mobilecoind.sh

This script starts mobilecoind and connects it to the nodes started by `local-network-5.sh`.

It has sane defaults and requires no extra configuration.
