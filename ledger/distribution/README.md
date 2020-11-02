## Ledger Distribution

Consensus participants in the MobileCoin network are encouraged to publish their ledgers to long-term storage, such as S3. Provided here is a simple utility you can run alongside your consensus service to push data to S3.

### Setup

You must obtain AWS credentials and set them in your env.

```
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=...
```

### Usage

```
cargo run --release -p mc-ledger-distribution -- \
    ---ledger-path /tmp/ledger \
    ---dest "s3://my_bucket/my_node.my_domain.com"
```
