# MobileCoin Core Library (`mc-core`)

This crate provides (`no_std` and alloc free) core functionality required to support MobileCoin wallets, including keys, addresses, and derivations (and in the future, ring signatures and transactions).

Types are defined in [`mc-core-types`](./types) for dependency loop avoidance.
Internal packages _should_ depend on `mc-core-types` unless functionality from `mc-core` is required, external packages _should_ depend on `mc-core` using re-exported types as internal arrangements may change.