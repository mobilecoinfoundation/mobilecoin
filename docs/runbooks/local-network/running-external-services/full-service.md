# Full Service

**Step 1:** Make sure [Full Service](https://github.com/mobilecoinofficial/full-service) is imported to your local environment and follow the setup procedure for it

**Step 2:** Copy the `consensus-enclave.css` file generated from the build on docker into the root directory of Full Service

**Step 3:** Run the following command

```
MC_SEED=<your seed generated during prerequisites step> \
SGX_MODE=SW \
IAS_MODE=DEV \
CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
cargo build --release -p mc-full-service
```

**Step 4:** Run the following command

```
mkdir -p /tmp/wallet-db/
./target/release/full-service \
    --wallet-db /tmp/wallet-db/wallet.db \
    --ledger-db /tmp/ledger-db/ \
    --peer insecure-mc://localhost:3200 \
    --peer insecure-mc://localhost:3201 \
    --tx-source-url file:///<path_to_local_mobilecoin_repo>/target/docker/release/node-ledger-distribution-0 \
    --tx-source-url file:///<path_to_local_mobilecoin_repo>/target/docker/release/node-ledger-distribution-1
```

If everything was successful, you should see no error about AttestationVerification or the like.

To get access to MOB, import an account into Full Service from the `target/sample_data/keys` directory (any account should work, they all have a huge amount of MOB)
