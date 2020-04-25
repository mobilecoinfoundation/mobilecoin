mc-sgx-libc-types
==============

Frequently when interfacing with C, we need C types like `c_int`, `uintptr_t`,
`c_void`, etc. which unfortunately are in rust `std` and not rust `core`.

To avoid typing these over and over in `no_std` crates we put them once here.
