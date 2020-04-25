mc-sgx-unwind
==========

This crate links in the version of `libunwind` C library which is bundled with
`rustc`, and provides a rust interface to it.

This can be used in the enclave to support printing backtraces during a panic,
and to support a `panic=unwind` configuration where panics can be caught like
exceptions.

This is analogous to the implementation in rust `std`, and also the Baidu
`rust-sgx-sdk`.

TODO(chbeck): It might also be an option to use `libunwind-sys` from crates.io
instead, rather than using whatever version they are bundling,
but neither rust `std` nor Baidu are doing that right now AFAICT
