## mc-common

This crate contains several things right now:

- Common structs that are used at API boundaries of higher-level crates
  Putting the structs in `common` instead of in a larger crate allows to break
  dependencies, and minimize the amount of code that compiles as `std` and `no_std`.
- Common error types, used at API boundaries. The rationale is similar.
- A shared hashmap object based on hashbrown that works in and out of the enclave.
- Logging functionality
