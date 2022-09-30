# Intel Attestation Report Verifiers

This crate contains a verification framework for examining a [`VerificationReport`](::mc_attest_core::VerificationReport) data for compliance with a pre-determined set of criteria, which is the core mechanism for authenticating attested connections.

The basic idea is a single [`Verifier`] structure, roughly following the builder pattern, which clients will construct in advance of connection creation based on their configuration (runtime or build-time). Clients will feed the `VerificationReport` structure provided by attesting services into the `Verifier`, which will return a pass/fail indication, along with the parsed report (for further debugging).

## Usage Example

```rust,ignore
use mc_attest_core::{MrEnclave, VerificationReport};
use mc_attest_verifier::{Verifier, MrEnclaveVerifier};
use mc_util_encodings::FromHex;

// Create a new status verifier for a MRENCLAVE measurement value
let mut enclave_verifier = MrEnclaveVerifier::new(MrEnclave::from_hex("BEEFCAFEDEADBEEFCAFEBEEF"));
// Whitelist the LVI hardening advisory (assume the BEEF... enclave is hardened)
// Whitelist the MMIO hardening advisory (assume the enclave uses [out] and 8-byte aligned writes)
enclave_verifier.allow_hardening_advisories(&["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"]);

// Construct a new verifier using hard-coded IAS signing certificates
let mut verifier = Verifier::default();
// Disallow debug enclaves
verifier.debug(false);
// Require enclaves to match the given MRENCLAVE value, and either have an OK status, or a
verifier.mr_enclave(enclave_verifier);

// Debug-log our verifier
dbg!(verifier);

// Example client
loop {
    let avr = get_verification_report();
    // Check the AVR, print the parsed report on failure (requires manual match vs. verifier)
    let _parsed_report = verifier.verify(&avr).expect("Could not verify report");
}

```
