mc-sgx-panic
=========

This crate provides support for panicking in sgx, and related standard APIs.

- `panic_handler` and `eh_personality` lang items, supporting use of `panic!`,
   `assert!`, etc.
- Equivalents of `std::panic::catch_unwind`, `std::panic::resume_unwind`
  `std::thread::panicking()`

In order to print backtraces and panic messages, this crate relies on OCALLs
that pass the text from the enclave to the untrusted code which prints them
to `stderr`. See `mc_sgx_urts` for implementation.

Features
--------

### Panic Strategy

You can select between a `panic=abort` or `panic=unwind` configuration by choosing
one of the features `panic_abort`, `panic_unwind`. You must select one of these
features.

### Alloc

`alloc` feature controls dependency on `alloc` crate, and availability of APIs
that require `alloc` crate, such as `catch_unwind`.

`panic_unwind` feature requires `alloc` feature.

In `panic_abort` + `alloc` configuration, the `catch_unwind` APIs will be available,
but they won't do anything special, exactly as in rust `std`.

### Backtrace

`backtrace` feature controls whether we attempt to collect backtraces in the
enclave and send them to untrusted.

This can be used in `panic=abort` and `panic=unwind` configurations but it
requires a similar dependency on `libunwind` in the enclave. (Which
is statically linked in by `rustc` for us anyways.)

Backtraces are not symbolicated in the enclave, they are symbolicated in
untrusted code on the other side of an OCALL.

Unfortunately, there is not a
simple way for the handler of the OCALL to figure out which enclave dispatched
the OCALL, and thereby figure out which on-disk file to open to look for symbols.

To get symbolicated backtraces, you must go to `mc_sgx_backtrace` crate in the
enclave and call the function `mc_sgx_backtrace::libpath::set`. It is recommended
to do this in an initialization ECALL that you call immediately after creating
the enclave and before any other threads access the enclave.

Dependencies
------------

- `alloc` feature => `alloc` crate
- `panic_unwind` feature => `mc_sgx_unwind` crate, `mc-sgx-libc-types` crate
- `backtrace` feature => `mc_sgx_backtrace` crate, and transitively `mc_sgx_unwind`

All configurations require the Intel C library `mc_sgx_trts` for `abort()` function.

Notes
-----

- We do not support creating a panic hook at run-time, as the rust standard
  library does.
