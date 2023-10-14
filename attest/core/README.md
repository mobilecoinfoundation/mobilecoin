# SGX Attestation Crate

This crate exists to support remote attestation via Intel SGX, albeit on a lower level than the Intel SGX messaging. This enables application selection of the enclave's key algorithms and negotiation, rather than Intel's selection of the NIST P256 curve. In particular, it provides:

 * A rust-like API for interacting with the SGX C library types and functions exposed by Baidu's rust-sgx-sdk.
 * Support for and linkage to the SGX SDK simulation libraries via a cargo feature.
 * An API for parsing and validating IAS verification reports in a `no_std` environment.
 * Common serialization for SGX data structures, as X86_64 C structs (to aid validation of structures on non-x86_64 platforms)
 * Common API for dealing with SGX structures, regardless of environment.

## Compile-Time Features

There are several compile-time features which change the behavior of this crate, as well as the API compatibility:

 * `std` - Enables the Rust standard library (this should not be used when built for an enclave).
 * `sgx-sim` - Selects the fake signing certificates generated at build time as the default verification certificates, and link against the `_sim.so` variants provided by Intel. Because this is dangerous, and should only be used during testing, a warning will be printed indicated what libraries are being linked.

## Usage

In general, users of this crate will want to use it to emulate much of the SGX
SDK process, albeit while staying within "safe" Rust wherever possible. For
example, for an enclave returning cached attestation evidence, the process will
look something like this:

 1. Untrusted calls `DcapQuotingEnclave::target_info()` to retrieve the `TargetInfo` quoting enclave.
 1. Untrusted provides the results to the enclave ("how" is undefined in this crate).
 1. Enclave calls `Report::new()` providing it the enclave's identity as `report_data`.
 1. Enclave returns the `Report` and `EnclaveReportDataContents` to the untrusted code.
 1. Untrusted uses `DcapQuotingEnclave::quote_report()` to communicate with the quoting enclave and get a quoted for the Enclave.
 1. Untrusted uses `DcapQuotingEnclave::collateral()` to get the other attestation evidence for the `Quote`.
 1. Untrusted sends the `DcapEvidence`, the combined; `Quote`, `EnclaveReportDataContents` and `Collateral` to the Enclave.
 1. Enclave verifies the signatures of the given evidence and that the `EnclaveReportDataContents` is that contained in the `Quote`.
 1. Enclave caches the `DcapEvidence` and provides it upon demand to clients.
