# Attestation Enclave Support

This crate contains a compatibility layer for SGX enclave support. The intent is that it can be used in both the enclave and a unit testing environment. When used in an enclave (which itself has no unit tests), the enclave crate itself should include this module directly and enable the `sgx` feature.

Other crates, which actually call the APIs in this crate, should only include it, and not enable the special `sgx` feature.
