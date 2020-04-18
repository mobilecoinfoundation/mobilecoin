mc-sgx-debug
=========

This crate exposes a macro like `eprintln!` from the rust standard library

Our version is supported instead by an OCALL to the untrusted code,
so this crate only works in sgx right now.

It is expected that this will only be used for debugging during development.
