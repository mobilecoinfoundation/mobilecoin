#"## Table of Contents

  - [Getting Started](#getting-started)
    - [Requirements](#requirements)
    - [Building for SGX](#building-for-sgx)
      - [Hardware Mode](#hardware-mode)
      - [Simulation Mode](#simulation-mode)
    - [Enclave Signing Material](#enclave-signing-material)
    - [Build](#build)

#### Requirements

The consensus service runs with a secure enclave with Intel's Secure Guard eXtensions (SGX).

A list of available SGX hardware providers can be found at: https://github.com/ayeks/SGX-hardware

Several cloud providers also offer SGX, with some requiring manual intervention during provisioning. We have experience with, and can recommend the following cloud providers:

| Cloud Provider | SGX Provisioning |
| -------- | -------- |
| [Microsoft Azure Confidential Compute](http://aka.ms/azurecc) | Automated. DC Series in UK South and Canada Central. |
| [IBM (formerly Softlayer's SGX product)](https://www.ibm.com/cloud/blog/data-use-protection-ibm-cloud-using-intel-sgx) | Manual. Must contact support after ordering. |
| [OVH](https://www.ovh.com/world/dedicated-servers/software-guard-extensions/) | Manual. Must contact support after ordering. |

If you are curious about the service, and don't have SGX hardware, you can build and run the consensus service in simulation mode on a non-SGX machine (see [Simulation Mode](#simulation-mode)).

#### Building with Docker

To ease environment set up, we provide a tool to set up a docker container with all the necessary SGX and proto libs.

```bash
# From the root of the repo
./mob prompt --hw


# At the container prompt
cargo build -p mc-consensus-service
```

>Note: The `--hw` flag loads the SGX device into the container, and configures the `SGX_MODE` environment variable to `HW` to use the device. If you are running in simulation mode, or buliding the binary without running it, you can omit this.

This will build using the provided Dockerfile specified at [docker/Dockerfile](../../docker/Dockerfile), similar to the following:

```bash
# From the root of the repo
docker build docker -t mobilecoin-image
docker run -v $(pwd):/tmp/mobilecoin --workdir /tmp/mobilecoin --device /dev/isgx -it mobilecoin-image /bin/bash
```

>Note: The SGX is loaded into the conatiner with `--device /dev/isgx`. If you are running in simulation mode, or building the binary but not running it, you can omit this.

#### Setting up your Environment

Please see our example Dockerfile in [docker/Dockerfile](../../docker/Dockerfile) for the current requirements to set up your environment for building consensus. We recommend Ubuntu 18.04.

You may also need to install the following to run consensus:

```bash
apt-get update -q -q && \
 apt-get upgrade --yes --force-yes && \
 apt-get install --yes --force-yes \
  build-essential \
  ca-certificates \
  cmake \
  gettext \
  libc6 \
  libcurl4 \
  libgcc-7-dev \
  libgcc1 \
  libnghttp2-14 \
  libprotobuf-c1 \
  libprotobuf10 \
  libstdc++6 \
  zlib1g && \
 rm -rf /var/cache/apt && \
 rm -rf /var/lib/apt/lists/*
```

#### Building for SGX

##### Hardware Mode

To run the consensus service, you need:
- [Linux SGX driver](https://github.com/intel/linux-sgx-driver)
- [Linux SGX SDK](https://github.com/intel/linux-sgx)
-  [API key obtained from Intel](https://api.portal.trustedservices.intel.com/EPID-attestation) to utilize their attestation services
>Note: A successful attestation of a hardware-enabled enclave is required to participate in consensus.

We provide an example install_sgx script that we use in our deployment in [docker/install_sgx.sh](../../docker/install_sgx.sh).

>Note: You will need to run the following as root.

Recommended SDK and package installation:

```bash
# Download Drivers, Setup SGX Package Repository 
(
	. /etc/os-release

	wget "https://download.01.org/intel-sgx/sgx-linux/2.13.3/distro/ubuntu${VERSION_ID}-server/sgx_linux_x64_sdk_2.13.103.1.bin"
	wget "https://download.01.org/intel-sgx/sgx-linux/2.13.3/distro/ubuntu${VERSION_ID}-server/sgx_linux_x64_driver_2.11.0_2d2b795.bin"

	echo "deb [arch=amd64 signed-by=/etc/apt/trusted.gpg.d/intel-sgx-archive-keyring.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu/ ${UBUNTU_CODENAME} main" > /etc/apt/sources.list.d/intel-sgx.list
)

# Install the SGX Repository Signing Key
wget -O- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | \
	gpg --dearmor > /etc/apt/trusted.gpg.d/intel-sgx-archive-keyring.gpg

# Install the EPID/OOT kernel driver
chmod +x ./sgx_linux_x64_driver_2.11.0_2d2b795.bin
./sgx_linux_x64_driver_2.11.0_2d2b795.bin

# Install the SDK to /opt/intel/sgxsdk
chmod +x ./sgx_linux_x64_sdk_2.13.103.1.bin
./sgx_linux_x64_sdk_2.13.103.1.bin --prefix=/opt/intel

apt install libsgx-uae-service sgx-aesm-service

source /opt/intel/sgxsdk/environment
```

##### Simulation Mode

For local testing, it is possible to run in simulation mode as well as with SGX hardware properly enabled. This mode mocks attestation.

Install the packages specified in [Hardware Mode](#hardware-mode) without running the daemons.

#### Enclave Signing Material

The enclave needs to be signed in order to run in production. The MobileCoin Foundation manages the key that signs the enclave which is used in the production MobileCoin Consensus Validator. You can pull down the publicly available signature material in order to run the enclave that will attest with other MobileCoin consensus validators.

##### Building without Signing Material

Building locally does not require providing a private key, as a random key will be generated during build.

##### Using a Signed Enclave

There are two ways to use materials from a previously signed enclave to build your enclave locally.

The TestNet signature artifacts are available via

```bash
curl -O https://enclave-distribution.test.mobilecoin.com/production.json
```

This retrieves a json record of:

```json
{
    "consensus": {
        "enclave": "pool/<git revision>/<signing hash>/<filename>",
        "sigstruct": "pool/<git revision>/<signing hash>/<filename>"
    }
}
```

The git revision refers to the TestNet release version.

Once you have the desired artifact, you will need to extract both the signed enclave and the sigstruct file to build:

MobileCoin's TestNet Signed Enclave materials are available at, for example:

```bash
 curl -O https://enclave-distribution.test.mobilecoin.com/pool/bceca6256b2ad9a6ccc1b88c109687365677f0c9/bf7fa957a6a94acb588851bc8767eca5776c79f4fc2aa6bcb99312c3c386c/libconsensus-enclave.signed.so
 curl -O https://enclave-distribution.test.mobilecoin.com/pool/bceca6256b2ad9a6ccc1b88c109687365677f0c9/bf7fa957a6a94acb588851bc8767eca5776c79f4fc2aa6bcb99312c3c386c/consensus-enclave.css
```

Then, when you build, you will provide both `CONSENSUS_ENCLAVE_SIGNED=$(pwd)/libconsensus-enclave.signed.so CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css`.

#### Build

To build consensus, you will need to specify the following:

* `SGX_MODE` (either `HW` for hardware or `SW` for simulation)
* `IAS_MODE` (depending on which EPID policy you registered for, either `DEV` or `PROD`)
* (Optional) Signing material, `CONSENSUS_ENCLAVE_SIGNED` and `CONSENSUS_ENCLAVE_CSS` (see [Enclave Signing Material](#enclave-signing-material) above)

And then you can build with:

```
SGX_MODE=HW IAS_MODE=DEV \
    CONSENSUS_ENCLAVE_SIGNED=$(pwd)/libconsensus-enclave.signed.so \
    CONSENSUS_ENCLAVE_CSS=$(pwd)/consensus-enclave.css \
    cargo build --release -p mc-consensus-service
```
