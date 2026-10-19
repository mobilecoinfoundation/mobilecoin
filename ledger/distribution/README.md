## Ledger Distribution

Consensus participants in the MobileCoin network are encouraged to publish their ledgers to long-term storage, such as S3. Provided here is a simple utility you can run alongside your consensus service to push data to S3.

### Setup

The AWS SDK discovers credentials from the environment, AWS profiles, or workload roles. For environment credentials, set:

```
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=...
```

Temporary credentials also require `AWS_SESSION_TOKEN`. AWS profiles can be selected with `AWS_PROFILE`; process credentials are supported, but SSO support is not enabled.

Region names retain Rusoto 0.48 compatibility: canonical names such as `eu-west-2` and shorthand names such as `euwest2` are accepted case-insensitively. The accepted region set is unchanged; whitespace is not trimmed.

The region is selected from the destination's first nonempty `?region=` parameter, then `AWS_REGION`, `AWS_DEFAULT_REGION`, the selected AWS profile, and finally `us-east-1`. An invalid nonempty URI region is rejected at startup. A present but empty or invalid environment region falls back immediately to `us-east-1`, without trying lower-priority sources. A missing or invalid profile region also falls back to `us-east-1`.

### Usage

```
cargo run --release -p mc-ledger-distribution -- \
    --ledger-path /tmp/ledger \
    --dest "s3://my_bucket/my_node.my_domain.com?region=eu-west-2"
```

The URI host is the bucket and its path is the object-key prefix. Uploads retain the `public-read` ACL. A `file:///path/to/directory` destination writes archives to local disk instead.
