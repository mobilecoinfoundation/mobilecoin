mc-light-client-verifier
========================

The mc-light-client-verifier module contains code for a stateless validation routine
which can verify, based on static configuration, that a given block was externalized
by the network, based on node signatures.

For convenience, it can also verify that a TxOut was externalized as part of a given block.

For more background on motivation, see https://blog.cosmos.network/light-clients-in-tendermint-consensus-1237cfbda104
