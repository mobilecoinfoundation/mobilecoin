# Consensus Enclave Omnibus

This collection of crates implements a "fully formed" interface for the `consensus_service` application to interact with its enclave, which is used to process inputs from clients. The "outer" `mc-consensus-enclave` crate is the one which the application will interact with, and it, in turn, will proxy requests to the actual enclave.

|Crate|Use|
|-----|---|
|`mc-consensus-enclave`|Application-facing proxy to object in the enclave|
|`mc-consensus-enclave-api`|Common API for app-facing proxy and internal enclave object|
|`mc-consensus-enclave-edl`|Enclave Definition Language (EDL) sources for code-gen|
|`mc-consensus-enclave-impl`|Internal enclave object|
|`mc-consensus-enclave-measurement`|Access to the SIGSTRUCT data for a built enclave|
|`mc-consensus-enclave-mock`|Simple mock object for use in unit testing|
|`mc-consensus-enclave-trusted`|The enclave-side of the proxy provided by the base crate|

The API implemented by this crate is contained within the inner `mc-consensus-enclave-api` crate, who's contents are re-exported by this crate for ease of use. The API is also used by the `mc-consensus-enclave-impl`, which runs inside the enclave.

The data flow, therefore is:

 1. Application makes an API call to `mc-consensus-enclave` using traits found in `mc-consensus-api`.
 1. `mc-consensus-enclave` serializes a request structure request into bytes, and calls `mobileenclave_call`.
 1. Generated code passes that through the SGX ECALL machinery into the corresponding `mobileenclave_ecall` definition in `mc-consensus-enclave-trusted`.
 1. `mc-consensus-enclave-trusted` deserializes the request structure, and gives it to the "real" implementation, which lives in `mc-consensus-enclave-impl`.
 1. Returned data is handled in a similar fashion as the stack is unwound.
 
 Therefore, the "base" crate contains a basic remoting implementation that proxies data into the enclave across the SGX boundary.
 
 The `mc-consensus-enclave-edl` crate contains build-time Enclave Definition Language (EDL) files which describe the code to be generated, and is used by both outer and `-trusted` crates. 
