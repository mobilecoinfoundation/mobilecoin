fog-ocall-oram-storage-testing
==============================

Normally, the `fog-ocall-oram-storage-trusted` crate is linked into an enclave,
and the `fog-ocall-oram-storage-untrusted` crate is linked into the untrusted application
that hosts the enclave, and this is mediated by the EDL interface.

However, because the EDL interface functions are C-compatible, we can also just link
both sides into one application, and they will interact over a normal C-ffi boundary
with no SGX involved. This works because the trusted side doesn't actually make any
enclave-specific calls, e.g. getting quotes and reports etc.

This test tries to exercise the functionality when the crates are built this way.
It depends on both `-trusted` and `-untrusted` crates.

We don't try to arrange this as a test using one of the sides, because cargo
`dev-dependencies` are sometimes buggy and can cause strange feature unification
problems, which can turn into wrongly linking `std` into the enclave or some other
such issue, and we don't want the possibility that this can break the enclave build
in a difficult-to-debug way. The trusted and untrusted crates are getting linked
together, when this crate is built, in a way that is different from how they are
linked in the rest of the project.
