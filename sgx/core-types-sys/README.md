FFI structures used by the Intel SGX process.

This no-std crate provides FFI types used by the Intel SGX attestation process: notably `sgx_status_t`, `sgx_report_t`, and `sgx_target_info_t` and their members. These types are not intended to be used directly, but rather wrapped by the `mc-sgx-core-types` crate, which will provide safe, rusty access to their contents.
