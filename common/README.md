common
======

This crate contains several things right now:

- Common structs that are used at API boundaries of higher-level crates
  Putting the structs in `common` instead of in a larger crate allows to break
  dependencies, and minimize the amount of code that compiles as `std` and `no_std`.
- Common error types, used at API boundaries. The rationale is similar.
- Forward declarations of functionality that is "common" to both inside and outside
  the enclave. For instance, `mchash` and `mcserial` types are forwarded from the
  `common` crate. This avoids needing to list these dependencies explicitly in
  all of the high level targets that use them.
- Constants associated to attestation. These appear in `ias_settings` module.
- Utility functions such as `for_each_set_bit`, which appears in `bits` module.
