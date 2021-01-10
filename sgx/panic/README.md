mc-sgx-panic
=========

This crate provides support for panicking in sgx, and related standard APIs.

- `panic_handler` and `eh_personality` lang items, supporting use of `panic!`,
   `assert!`, etc.
- Equivalents of `std::panic::catch_unwind`, `std::panic::resume_unwind`
  `std::thread::panicking()`

In order to print panic messages, this crate relies on OCALLs
that pass the text from the enclave to the untrusted code which may log them.
See `mc_sgx_urts` for implementation.

Features
--------

### Panic Strategy

The only panic strategy currently implemented is `panic=abort` due to security
concerns about the unwind functionality.

Presently the `panic_abort` feature is on by default and it is not supported to
turn it off.

Implementing the `panic_unwind` feature will require research and design.
We nevertheless preseve the `catch_unwind` and `resume_unwind` standard apis,
which don't do anything special in the `panic=abort` configuration.

### Alloc

`alloc` feature controls dependency on `alloc` crate, and availability of APIs
that require `alloc` crate, such as `catch_unwind`.

In `panic_abort` + `alloc` configuration, the `catch_unwind` APIs will be available,
but they won't do anything special, exactly as in rust `std`.

Dependencies
------------

- `alloc` feature => `alloc` crate

All configurations require the Intel C library `mc_sgx_trts` for `abort()` function.

Notes
-----

- We do not support creating a panic hook at run-time, as the rust standard
  library does.
