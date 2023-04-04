# mc-transaction-summary

This crate provides types and implementations for computing transaction summaries and associated reports, used in the calculation of the extended message digest for construction of transactions in block versions >= 3 and allowing hardware devices or offline-signers to generate reports to verify the contents of a transaction prior to signing.

A high-level `verify_tx_summary` function is provided to check the a summary against a transaction using `TxSummaryUnblindingData` and `TxOutSummaryUnblindingData` types, avaialable under the `default` or `mc-account-keys` features.

A `no_std` compatible streaming interface `TxSummaryStreamingVerifierCtx` for verifying transaction summaries and generating associated reports, for use in memory-constrained contexts such as hardware wallets.

