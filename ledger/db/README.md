# mc-ledger-db

Persistent storage for the blockchain.

This crate defines a `Ledger` interface and an LMDB implementation of a blockchain data store. The MobileCoin blockchain redacts the inputs and signatures for each transaction.

For improved query efficiency, some data is duplicated outside of the block in additional LMDB indices.

### References
* [LMDB Caveats](http://www.lmdb.tech/doc/index.html#caveats_sec)
* [LMDB Usage and Recommendations](https://rchain.atlassian.net/wiki/spaces/CORE/pages/57344008/Lmdb+and+Lmdbjava+Usage+Recommendations)
