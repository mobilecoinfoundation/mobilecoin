mc-sgx-urts
========

This crate provides support for *untrusted* code outside the enclave, that wants
to spin up enclaves.

It provides:

* An object-oriented rust API for spinning up enclaves, given a path to an
  appropriate shared library
* Implementations of OCALLs which are made by our various trusted crates.

Dependencies
------------

`mc_sgx_urts` has few dependencies outside the rust standard library.

Feature selection can be used to pare this down more if you aren't using all
the OCALLs in your enclave.
