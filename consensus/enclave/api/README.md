# MobileCoin Enclave API

This crate contains the untrusted-facing APIs for a MobileCoin enclave. The goal is to provide an API to the enclave that interacts as a special-case of the more commonly understood object remoting. In particular, there should be an "untrusted" implementation of these APIs which lives in the node, and a "trusted" implementation of these APIs which lives in the enclave.

This particular use of remoting, where we simply want to cross a trust boundary that lives within the same process on the same machine, is significantly simplified from the typically-maligned *networked* remoting, and is therefore significantly less insane than most remoting frameworks. In this model, the typical workflow is something akin to this:

 1. Untrusted API method is called.
 1. Untrusted method transforms the parameters given into a serializable message.
 1. Untrusted serializes the message into a byte array, and calls the (single) enclave entry point (via `ECALL`), and gives it the byte array as a pointer, and another byte array for the enclave to store the return value in.
 1. The enclave deserializes the message, finds the relevant object, and calls it's method with the parameters extracted from the deserialized message.
 1. The in-enclave object performs whatever usual work it would perform, and returns a typical Rust `Result` structure.
 1. The enclave serializes the `Result` into a byte array, and copies it into the output byte array provided with the `ECALL`.
 1. The untrusted deserializes the output byte array's return value, and returns from it's own API method.

It may help to describe this as a call stack:

 * Untrusted: `EnclaveProxy::frobnicate(Frobnication) -> Result<FrobOut, FrobErr>`
 * Untrusted: `mobilenode_call(enclave_id, bytes_of_frobnicate_msg, &mut output_bytes) -> sgx_status_t`
 * Enclave: `mobilenode_call(bytes_of_frobnicate_msg, &mut output_bytes) -> sgx_status_t`
 * Enclave: `EnclaveImpl::frobnicate(Frobnication) -> Result<FrobOut, FrobErr>`

In particular, `Frobnication` will be stuffed into a `Call::Frobnicate(Frobnication)` enum, and serialized to become `bytes_of_frobnicate_msg`, and the Enclave's `Result<FrobOut, FrobErr>` will be serialized and copied into `output_bytes`, and the untrusted `EnclaveProxy::frobnicate` implementation will then deserialize that back into it's `Result` structure and return it.

## Traits

At the moment, we have two traits: `ReportableEnclave`, which provides a way for the untrusted code to seed the IAS `VerificationReport` cache using the structures in `attest`, and `PeerableEnclave`, which is intended to support the node-to-node attestation via the gRPC API defined in `attest_api`. We anticipate adding a `BlockEnclave` to support the APIs needed by the SCP externalization phase, and an additional `ClientEnclave` to support client connectivity using the same gRPC API defined in `attest_api` (albeit on a different port).
