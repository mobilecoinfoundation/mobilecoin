mc-crypto-ring-signature
========================

This crate implements a few fundamental parts of MobileCoin transactions:

* MobileCoin amount commitments. These are Pedersen commitments to numbers which
  represent an amount of some token on the blockchain, in the smallest representable units.
* MobileCoin ring signatures. These are MLSAG ring signatures (see Ring CT) which sign over
  several amount commitments together with their "address". The signer knows the "one-time private key"
  of only one of these, but the signature does not reveal which one it is. This signature
  confers spend authority for a value in the blockchain. However, there may be many of these in a
  single MobileCoin transaction. The entire assembly is defined in the `ring_ct` module in
  `mc-transaction-core`.
* Definitions for "one-time keys" and their connection to transaction outputs and subaddresses.
