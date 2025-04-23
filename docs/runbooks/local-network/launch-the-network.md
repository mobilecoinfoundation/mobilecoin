# Launch the Network

**Step 1:** Set the following environment variables in your docker container

```
export MC_SEED=<seed generated from prerequisites>
export LEDGER_BASE=/tmp/mobilenode/target/sample_data/ledger
```

**Step 2:** Run the following command

```
python3 local_network.py --network-type a-b-c
```

After some time, the network should now be running!

If you run into an error like this

```
Generating minting keys \ /bin/sh: 1: exec: target/release/mc-util-seeded-ed25519-key-gen: not found
```

You may have to modify the `local_network.py` script and change `TARGET_DIR` to `target/docker/release`
