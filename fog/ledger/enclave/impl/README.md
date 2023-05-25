# Ledger Enclave API Implementation

This is the in-enclave implementation of the traits defined in `fog_ledger_enclave_api`. In particular, it provides the `SgxLedgerEnclave` struct, which implements the inside-the-enclave version of the `LedgerEnclave` trait.

## Future Work

Currently this crate provides prostified versions of the client-facing encrypted parameters.  We would like to generate these from the external protobufs to avoid the code duplication and possible conversion errors.

The SgxLedgerEnclave currently does no actual work, it simply terminates the attested connection and decrypts the client parameters to pass back to untrusted to process in the clear.  Eventually we want the actual data to live in ORAMs; when this is the case, the enclave will instead tell untrusted to load an ORAM path.  Untrusted will then pass this path back to the enclave in the second phase of the transaction, which will use the ORAM path to determine the response and encrypt back to the user.  At this point the service will be completely oblivious, with no data or access patterns available to untrusted code.  Key image checks will be the prototype ORAM.
