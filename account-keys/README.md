mc-account-keys
===============

This crate defines structures that represent the private keys to a MobileCoin account,
and the public keys that correspond to a MobileCoin public address.

It also defines how public addresses are derived from account keys, and how to
serialize them in the protobuf format.

There are some additional details about
- Subaddresses
- View key (see [Cryptonote documentation](https://cryptonote.org/cns/cns007.txt))
- Creating the fog authority signatures, for accounts that have a fog service
