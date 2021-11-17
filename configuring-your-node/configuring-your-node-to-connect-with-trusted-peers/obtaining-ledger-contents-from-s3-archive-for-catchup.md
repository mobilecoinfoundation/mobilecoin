# Obtaining Ledger Contents from S3 Archive for Catchup

The `tx_src_urls` section of the network.toml specifies the locations to search for obtaining ledger contents from your trusted peers’ public archive backups. These are provided as a list of S3 bucket URLs, and catchup involves:&#x20;

1. Get quorum’s current agreed block height and check against current local block height.&#x20;
2. If behind, round-robin through the `tx_src_urls` to pull blocks from S3.

