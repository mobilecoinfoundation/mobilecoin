mc-sgx-compat
==========

Compatibility layer for enclave-only crates.

Many times, applications want to have critical code that becomes part of an enclave,
but lives in a separate crate, and has unit tests, so that it can be easily built using `cargo test`.

This becomes complex when this crate must also contain mutexes -- if you use `mc_sgx_sync` mutexes
then your test won't compile, and if you use `std` mutexes then your enclave won't compile.

`mc_sgx_compat` attempts to create a compatibility layer so that you can meet this engineering need.
It is a facade which forwards functionality from the lower level crates, or forwards functionality from `std`
as needed for tests vs. enclaves.

Example usage:

```
/// Resolves to mc_sgx_sync::Mutex when we are ultimately part of an enclave, and std::sync::Mutex in e.g. tests or non-sgx targets
use mc_sgx_compat::sync::Mutex;

...
```

Note that there are significant limitations of cargo that impede us here:
- Because cross-compiling with cargo for sgx has limited support, we don't use gating based on `target_env`.
  We assume the enclave code is being compiled using the standard, "default" x86 linux target, using `no_std` to break OS dependencies.
- We could try to use feature gating based on the cargo `test` feature, but cargo doesn't let you turn dependencies off
  when features come on, so that wouldn't enable us to create a conditional dependency on `mc_sgx_sync` as needed.
- Instead, we create a new feature `sgx` which becomes the condition for this compatibility layer.
  Because `std` dependencies are calculated in rustc and not cargo, it is possible to turn off `std` when `sgx` feature
  comes on.
- It is recommended that your "business logic" crates should depend on `mc_sgx_compat` facade, with default features = false, so
  that it is testable.
- It is recommended that your final `libenclave.so` target should depend on `mc_sgx_compat` and set `features = sgx`, so that by
  cargo feature unification, all its dependencies get the sgx implementations.
- It is NOT recommended that your crates adopt an `sgx` feature and forward it to `mc_sgx_compat` as needed, you should let the
  final enclave target configure that directly, to avoid additional fragile plumbing and boilerplate.
- It is NOT recommended that your crates depend directly on `mc_sgx_sync` and similar lower-level crates, if you want them to be
  testable then they should get these things from `mc_sgx_compat`. (Or, you should position them under `mc_sgx_compat`.)

Configuring
-----------

Our `mc_sgx_compat` facade is not suitable for all users -- some users may want to use a different allocator,
or different panic code, or different logging code. They may have a business need to make the deployed enclave footprint
as small as possible to avoid expensive security audits of code they don't actually need.

We would like to make this as lightweight and configurable as possible, but unfortunately we are again constrained
by limitations of cargo. Cargo allows that dependencies can be made optional and selectively turned on by features,
but only in the limited sense that a single feature implies a dependency. It is impossible for us to say e.g.
"If `sgx` feature is on, and `sync` feature is on, then depend on `mc_sgx_sync` crate", in the Cargo.toml specification language.
And this is what we would have to do to make the sync code optional, and support the `sgx` vs. `std` switching.

So what I suggest is that if you want a minimal subset of these `sgx` crates for your enclave, you should not use our
`mc_sgx_compat`, you should simply copy it and make your own facade. There is hardly any code in this facade anyways,
and the crates underneath this crate have been designed to have minimal dependencies on one-another, so you hopefully
should not have too much trouble.
What cross-dependencies there are between them, generally have emerged because of how the rust standard library is
implemented anyways.

This is often the most maintainable pattern if your project has many crates (and possibly many enclaves),
because it means that the configuration options on `mc_sgx_panic`, `mc_sgx_sync`, `mc_sgx_alloc`, etc. appear only once
in your facade's Cargo.toml and not in multiple place. When multiple things depend on `mc_sgx_sync` it may be harder
to figure out how cargo will ultimately configure it due to feature unification.
