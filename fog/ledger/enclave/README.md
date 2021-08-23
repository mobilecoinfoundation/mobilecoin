# Enclave Interface Definition for the MobileCoin Ledger Node

This crate defines the interface of the SGX enclave used by a ledger node. This interface is comprised of ECALLs that help the ledger node to securely communicate with clients, to securely (and eventually obliviously) gather mixins and check whether key images have been spent.


This crate contains several files for configuring and building an enclave:

- `Enclave.edl` - Defines the ECALLs and OCALLs of the enclave interface.
- `Enclave.lds` - A custom linker script, used to hide unnecessary symbols.
- `Enclave.config.xml` - Config file, e.g. maximum number of threads inside the enclave, max heap size, etc.

During the build process, the Edger8r tool generates several C wrapper files from `Enclave.edl`:

- `Enclave_t.h` - Prototype declarations for trusted proxies and bridges.
- `Enclave_t.c` - Function definitions for trusted proxies and bridges.
- `Enclave_u.h` - Prototype declarations for untrusted proxies and bridges.
- `Enclave_u.c` - Function definitions for untrusted proxies and bridges.

# References

- [Enclave Definition Language (EDL) syntax](https://download.01.org/intel-sgx/linux-2.5/docs/Intel_SGX_Developer_Reference_Linux_2.5_Open_Source.pdf#page=39)
