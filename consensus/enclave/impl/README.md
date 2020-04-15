# MobileCoin Enclave API Implementation

This is the in-enclave implementation of the traits defined in `enclave_api`. In particular, it provides the `ReportingEnclave` and `PeeringEnclave` structs, which implement the inside-the-enclave version of the `ReportableEnclave` and `PeerableEnclave` structures.

## Future Work

As with `enclave_api`, we anticipate adding new structures to support client-facing transaction inputs and also the block-externalization process.

## Deep Thoughts

One problematic aspect of this crate (and the model promoted by `enclave_api`) is the fact that these various enclave structures are stored as mutex-protected singletons within the enclave. As a result, the `PeeringEnclave` needs to acquire a lock on the `ReportingEnclave` in order to retrieve a copy of the cached verification report.

Similarly, a hypothetical `ClientFacingEnclave` would need to acquire a lock on the `PeeringEnclave` structure in order to re-encrypt a message for transmission to peers, and both the `PeeringEnclave` and `ClientFacingEnclave` would need to acquire a lock on the `BlockEnclave` when attempting to add a new transaction to the block.

One option for this is to simply take care with this code and ensure that any locking is well-documented and well-behaved. Another option is to walk this back to a single mutex, but this has the disadvantage of effectively serializing all enclave communications into a single thread, which I believe will be too slow in practice. Yet another option is to introduce an "unlocked" dependency injection, wherein all the dependent singletons required for an operation are provided at runtime, though I believe this will have similar performance characteristics to the single-global-lock case, in practice.

The next option is to instantiate a new zero-width type at the `mobileenclave_call` ECALL site, and let those ZWTs utilize independently locked caching structures to perform their operations. That is, rather than locking on a `ReportingEnclave`, make `ReportingEnclave` a shim to access a set of mutex-protected `HashTable` structures.
