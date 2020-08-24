## mc-common

This crate contains several things right now:

- Common structs that are used at API boundaries of higher-level crates
  Putting the structs in `common` instead of in a larger crate allows to break
  dependencies, and minimize the amount of code that compiles as `std` and `no_std`.
- Common error types, used at API boundaries. The rationale is similar.
- A hashmap object based on hashbrown that works in and out of the enclave.
- A simple LRU cache implementation
- Logging functionality. Some of this is enclave compatible, some isn't,
  this is controlled by `log` and `loggers` features.

Note (enclave logging)
----------------------

The `mc-sgx-slog` crate provides an `slog::Logger` appropriate for the enclave.
It is recommended to refer to `mc_common::logger::Logger` in the portable `enclave-impl` crates,
and put the calls to `mc-sgx-slog` in the `enclave-trusted` crates.
