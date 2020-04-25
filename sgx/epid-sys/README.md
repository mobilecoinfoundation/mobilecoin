This crate provides FFI access to the EPID remote attestation functions provided by the the Intel SGX SDK. That is, those functions related to communicating with the Intel Quoting Enclave via the aesmd process to retrieve an `sgx_quote_t`.

As such, this crate is not intended to be use directly, please see `mc-sgx-epid` for the safe rust APIs.
