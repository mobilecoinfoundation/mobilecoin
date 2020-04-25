## sgx

This collection of crates can be used to construct a light-weight `no_std` rust
environment for use inside an sgx enclave. The assumption is that your enclave
builds for a "standard" x86-linux target and breaks OS dependencies by using `no_std`,
rather than using cross-compiling with `cargo` or `xargo` features.

Unlike the rust `std` library, these crates are modularized and don't have hard
dependencies on one-another, and are highly configurable using cargo features.

You can use this to make an enclave in rust with as small a code footprint and
enclave interface as possible. This approach may minimize attack surface and
ease security audits.

We also provide a ready-for-use facade (see `sgx_compat`) which forwards SGX versions
of `std` functionality like `Mutex`, or the `std` version, conditionally, to enable
making crates that are easily `cargo test`-able, and run in the enclave.

Acknowledgements:
-----------------

Some of this code is indeed factored out of rust `std` and the Baidu [`rust-sgx-sdk`](https://github.com/baidu/rust-sgx-sdk).
However, the goal of this project is different from Baidu `rust-sgx-sdk`.

We are not trying to create a drop-in replacement for the entire rust standard library,
and then patch third-party dependencies to compile against it.

Rather, we take a stricter point of view that third-party dependencies that need to talk to the
OS may not be appropriate to run in the enclave. Making an OCALL out of the
enclave in order to make a system call to support such applications may expose
vulnerabilities, see Iago attacks.

Instead we are advocating to stick to third-party crates that already
support building in a `no_std` configuration, because they don't talk to the OS,
(such as crypto and serialization libs), and use them without changes in
your enclave. (Or, take third-party crates that don't yet build as `no_std` but
could, patch them to fix this, and use this version in your enclave, while also
sending the patch upstream.)

The crates in this collection are mainly about providing things like `lang_items`
that are required in `no_std` builds in a way that makes sense for Sgx, and providing
things like synchronization primitives in way that drops in for `std::sync`
but wraps the Intel-provided versions.

Crates:
----------------------------

Some of these crates only work in enclave targets, some of them only work
in untrusted code running outside the enclave, and some of them are portable
to both places.

Enclave crates:

| Crate       | Description | Rust Dependencies | Intel Dependencies |
| ----------- | ----------- | ------------      | -----------        |
| `mc-sgx-alloc` | Provides a rust allocator, supports use of unstable `alloc` crate. Calls out to intel `malloc` and `free`. | None, but relies on panicking for OOM support by default | Intel `sgx_tstdc`, plus `sgx_trts` in `oom_abort` configuration |
| `mc-sgx-panic` | Supports use of core `panic!`, `assert!` macros, and optionally the `catch_unwind` APIs | None, but `unwind` support needs `alloc`, `mc-sgx-unwind`, `mc-sgx-libc-types`. Backtrace on panic also if `mc-sgx-backtrace` is available | Intel `sgx_trts` |
| `mc-sgx-sync`  | Provides Rust synchronization primitives similar to `std::Mutex` based on intel implementation. | `mc-sgx-panic` by default, `mc-sgx-types` | Intel `sgx_tstdc` |
| `mc-sgx-debug` | Provides a macro equivalent to `eprintln!` for use in sgx | None | None |
| `mc-sgx-enclave-id` | Provides a way to get the `enclave-id` from inside the enclave | None | None |
| `mc-sgx-backtrace` | Provides support for collecting backtraces and sending them to untrusted | `mc-sgx-unwind`, `mc-sgx-enclave_id`. Optionally `mc-sgx-debug` for printing certain warnings |

Additional enclave support crates:

| Crate       | Description | Dependencies |
| ----------- | ----------- | ------------ |
| `mc-sgx-unwind` | A rust interface to C `libunwind` which is bundled with rustc, libgcc | `mc-sgx-libc-types` crate |

Crates for outside the enclave:

| Crate     | Description | Dependencies |
| --------- |------------ | ------------ |
| `mc-sgx-urts` | This crate suports untrusted code that creates an enclave. It also contains OCALL implementations. | rust `std`, `mc-sgx-libc-types`, and for backtraces, `rustc_demangle` and `backtrace_sys` |
| `mc-sgx-build` | Shared code for build.rs scripts that link to SGX | |

Cross-platform crates:

| Crate       | Description | Dependencies |
| ----------- | ----------- | ------------ |
| `mc-sgx-types` | Provides some useful structs and typedefs, used to interface with sgx in and out of enclave | None |
| `mc-sgx-libc-types` | A small `no_std` replacement for ffi types in sgx | None |
| `mc-sgx-compat` | A facade re-exporting the enclave-only crates, with a switch to export `std` versions instead. This makes it easy to use these crates while still being able to `cargo test` your code. | All of the above |

`edl/`
---------------

These `edl` files contain any enclave ECALLS and OCALLS required by the crates
in `sgx/`.
The matching implementations of such OCALLs should be in `mc-sgx-urts`.
