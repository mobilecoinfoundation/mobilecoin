mc-sgx-alloc
=========

This crate provides a custom rust allocator for use in the enclave target.

We follow the pattern for custom allocators described here:
https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html

To implement the required functions, we follow the implementation from
`rust-sgx-sdk` in the `mc-sgx-alloc` crate:
- we link to `sgx_tstdc` C library provided by intel
- call the versions of `malloc`, `free`, etc. that they provide.

The `src/enclave` target should use the allocator by simply putting
`extern crate mc_sgx_alloc;` in their `lib.rs` file. It is expected that standard
library containers like Vec will work in the enclave after that.
