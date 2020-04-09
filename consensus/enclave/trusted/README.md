# Consensus Enclave Entry Point

This crate defines the entry point method (ECALL) for the MobileCoin consensus enclave, `mobileenclave_call()`, and bundles it into a rust library. The call itself handles serialization, deserialization, panics, and buffer-size related call retries internally, but dispatches to the associated `consensus_enclave_impl` crate for actual work.

Additionally, it defines compile-time flags for the rest of the enclave ecosystem.
