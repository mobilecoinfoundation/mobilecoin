A programmatic interface to Signal's patched llvm-bolt utility.

This crate will download and compile the `llvm-bolt` utility, as patched by Signal, and provide a Rustic builder interface to execute it, assuming the `OUT_DIR` is unchanged.

This is intended to be called from our enclave builder as a post-processing step on the unsigned enclave binary, in order to insert the LFENCE instructions necessary to mitigate micro-architectural vulnerabilities which require compiler assistance.

Enclaves which have been built with this mitigation should be considered safe to run in the presence of IAS responses which indicate `SW_MITIGATION_NEEDED` due to [INTEL-SA-00334](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00334.html).
