mc-sgx-backtrace
=============

This crate provides backtrace *tracing* functionality based on `libunwind`, very
similar to how rust `std` does it.

It does not provide support for *symbolicating* and *printing* the backtrace.
It is intended that frames should be symbolicated outside the enclave.

(See also the related `fortanix` sgx implementation in rust stdlib:
`rust/src/libstd/sys/sgx/backtrace.rs`)

This crate does provide support for sending unsymbolicated frames to untrusted.
(For easiest api, use `mc_sgx_backtrace::collect_and_send_backtrace()`.)

For convenience, this crate also provides support for storing the name of the
file associated to the enclave.

If the frames are passed to an OCALL in order to
print them, this filename can be passed along, if it was set by the user, so
that they can be automatically symbolicated there. Setting this filename is not
required to support the functionality in this crate, it is merely expected to
help the downstream consumer of the backtrace.

Features
--------

By default we rely on `mc_sgx_debug` crate to log certain warnings if backtracing
goes awry.
