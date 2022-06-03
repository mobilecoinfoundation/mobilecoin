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

This crate implicitly defines relationships between a bunch of key components:
* One-time private keys and TxOut's
* One-time private keys and Key Images
* One-time private keys of TxOut's and subaddresses
* Subaddreses and Ring signatures

However, most things having to do with the TxOut Public key and the TxOut shared secret
live in the `mc-transaction-core` crate, one level higher. Most of the actual blockchain
data structures are defined there.
