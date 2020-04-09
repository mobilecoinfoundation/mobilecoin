# Remote Attestation Crate

This crate provides support for Intel SGX remote attestation, and is based on types provided by the related `attest` crate. In particular, this crate provides the `RaClient` trait, which has two methods, `RaClient::get_sigrl()` and `RaClient::verify_quote()`. These methods take the `EpidGroupId` and `Quote` types from the `attest` crate, and use them to perform remote attestation by retrieving a `SigRL` and IAS `VerificationReport`, respectively.

In particular, there are two (current) implementations of `RaClient`. `IasClient`, which contacts IAS and performs the "normal" IAS remote attestation, and `SimClient`, which always returns an empty `SigRL`, and generates a fake IAS verification report and signs it using the fake, simulation keys which are generated at build-time and build-in to the resulting binaries.

## Future Work

The most obvious future work entails support for Intel Data-Center Attestation Primitives. At minimum, this will require a client which can be configured where to talk to, which will entail a change to/removal of `RaClient::new()`.
