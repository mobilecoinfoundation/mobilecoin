# Distributing Ledger Contents to S3 Archive

The main purpose of a consensus validator node is to agree on whether a transaction is valid, and write that transaction to the ledger. We encourage node operators to offer the ledger publicly via an S3 Archive for three reasons:

* Allows clients to sync the ledger from multiple nodes that they trust
* Allows independent auditing of transactions and block signatures
* Allows peers to obtain blocks they missed while they are in catchup

The `ledger-distribution` process runs in the container, and is configured by the AWS environment variables provided to the container.

**The parameters to ledger-distribution are set by default in the container, and include:**

| Parameter       | Value                    | Function                                                                                                                                                                                      |
| --------------- | ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--ledger-path` | Path to local ledger     | New blocks added to the local ledger will be synced to S3.                                                                                                                                    |
| `--start-from`  | “next” “last” or “zero”  | Indicates whether to start syncing from the next block appended to the ledger, the last written block, or from the origin block. Default is “next,” to not overwrite blocks in S3 on restart. |
| `--dest`        | S3 path to ledger bucket | Set by the `AWS_PATH` environment variable. **Note:** `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` must also both be set, containing credentials with write permissions to the bucket.     |

****

