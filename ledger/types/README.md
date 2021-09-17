ledger-types
============

The `ledger-types` crate defines some protobuf schema types like `BlockData` containing
all of the data that we store about a block.

The `BlockData` corresponds to a protobuf schema in the `mc-api` crate.

The `BlockData` includes not only the block header
and the block contents, but also surrounding data not technically part of the chain,
such a block signature, and including some attestation types, like an
Attestation Verification Report which supports the block signatures.

Because the `BlockData` depends on some attestation primitives from `mc-attest-core`,
it is not appropriate to put it in `mc-transaction-core`, which would make it impossible
to build transactions without also building SGX primitives. (This would greatly hinder
the development of hardware wallets, which likely cannot build `mc-attest-core`.)

Similarly, we don't want to put `BlockData` type in the `ledger-db` crate, because
this would make it impossible to build `mc-api` without building lmdb for your platform.

Since this is a schema type related to ledger serialization, and not directly bound to the
transaction math, we opted to move this to a light-weight `types` crate associated to
the ledger.
