A programmatic interface to [Signal's patched `llvm-bolt` utility](https://github.com/signalapp/BOLT).

This is intended to be called from our enclave builder as a post-processing step on the unsigned enclave binary, in order to insert the LFENCE instructions necessary to mitigate micro-architectural vulnerabilities which require compiler assistance. It does assume the correctly patched `llvm-bolt` can be found in the path. A script which will download and install this patched utility is [available in the mobilecoin repository](../../../docker/install-bolt.sh).

Enclaves which have been built with this mitigation should be considered safe to run in the presence of IAS responses which indicate `SW_MITIGATION_NEEDED` due to [INTEL-SA-00334](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00334.html).
