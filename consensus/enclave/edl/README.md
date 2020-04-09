# Consensus Enclave ECALL/OCALL Definitions

This crate contains a simple `enclave.edl` file which contains function prototypes used by the `edger8r` commands to generate wrappers. This crate itself simply exports the location of the EDL file to dependent crates via the cargo key/value pair system.

Downstream creates will those variables to find the EDL file at build time, so they can generate the necessary code.
