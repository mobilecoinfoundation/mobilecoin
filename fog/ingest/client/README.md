## ingest_client

The `fog_ingest_client` is a grpc client the connects to the `fog_ingest_server`.  There is a command line binary which exposes APIs needed to do various tasks.


## add-users
The add-users command is used to add users to an ingest server, either from public keys passed via command line (`--public-key`) or by reading a directory containing key files.

For example:
```
    cargo run -p fog_ingest_client -- \
        --uri fog-ingest://ingest.test.mobilecoin.com:443 \
        add-users \
        --keys-path sample-keys/fog-keys \
        --public-key 1234567890123456789012345678901212345678901234567890123456789012
```
