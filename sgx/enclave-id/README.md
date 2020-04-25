mc-sgx-enclave-id
==============

This crate provides functionality for enclave code to learn its own sgx enclave id.

This is particularly useful when using OCALL's, and when trying to design an enclave
so that multiple copies of the same enclave can exist. Sometimes this will happen naturally
during testing.

Unfortunately there is no built-in way to do this: https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/808786

`mc_sgx_enclave_id` provides an atomic variable to store the enclave_id, and an interface
to get it before making an OCALL. It is also integrated with `mc_sgx_urts` so that the enclave
gets told its ID when it starts, and this detail doesn't need to become part of a "high level"
rust enclave api.
