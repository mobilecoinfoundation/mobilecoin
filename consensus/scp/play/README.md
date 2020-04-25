## Intro

The `scp_play` utility is used to replay SCP logs created by `consensus-service` against a fake local node. This will hopefully be useful when needing to debug panics of `consensus-service` that are related to SCP.

Notes:
1. Currently `consensus-service` only holds logs for the most recent slot, so if having greater visibility is needed that would need to be changed.
1. `consensus-service` will only store logs when started with the `--scp-debug-dump` command line argument (which is the case for our deployed test networks and optionally the case for a local_services network).

## Usage with `local_services`

1. When running local_services, e.g. `./full-network-5.sh`, add an environment variable named `SCP_DEBUG_DUMP` pointing to a directory at which the logs should be stored. For example: `SCP_DEBUG_DUMP=/tmp/scp ./full-network-5.sh`
1. Perform some transactions to cause nodes to produce SCP traffic and logs. A subdirectory for each node would be created in the log directory.
1. Run `scp_play`: `MC_LOG=trace cargo run -p mc-consensus-scp-play -- --scp-debug-dump /tmp/scp/4`

## Usage with a Jenkins cloud deployed network

1. Log files are stored in `$HOME/scp-debug-dump/<node id>`, e.g. `$HOME/scp-debug-dump/node3.test.mobilecoin.com:8443/`.
1. You will need to SSH into the machine (as the `mobilecoin` user), and grab the logs: `sudo tar -czvf /home/mobilecoin/scp.tgz -C $HOME/scp-debug-dump/ .`
1. From your machine, scp the files: `scp mobilecoin@node3.test.mobilecoin.com:~/scp.tgz .`
1. Extract the archive and run `scp_play` (inside `public/`): `MC_LOG=trace cargo run -p mc-consensus-scp-play -- --scp-debug-dump /tmp/node3.test.mobilecoin.com:8443/`
