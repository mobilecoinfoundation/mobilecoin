view_protocol
=============

The view protocol crate contains logic around conducting the polling for new transactions
based on fog kex rng's. This crate abstracts the grpc connection behind a trait
and is meant to be grpc-agnostic, and even, libmobilecoin-friendly, meaning it should
not contain any networking or synchronization primitives.
