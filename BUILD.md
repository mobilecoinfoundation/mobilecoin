Build
=====

#### Build environment

Services that create SGX enclaves depend on the Intel SGX SDK. This must be installed
in the build environment, as well as the runtime environment.

## Dockerized build

An easy way to get this environment is to build in the docker image that we use for CI.
The dockerfile for this image lives in `docker/Dockerfile`.

You can use `./mob prompt` to pull this image, (or to build it locally), and get a prompt
in this environment.

```
# From the root of the repo
./mob prompt

# At the container prompt
cargo build
```

If you have SGX-enabled hardware (activated in BIOS, and with SGX kernel module installed),
you can use `./mob prompt --hw` to get SGX in the container. Then you can both build and
run the tests in `SGX_MODE=HW`. (See below for an explanation.)

## No-docker build

A docker-less build also works fine for development:
- Follow instructions [consensus/service/BUILD.md](consensus/service/BUILD.md)
- Set up your environment like the [Dockerfile](docker/Dockerfile)

#### Build configuration

There are two project-wide SGX-related configuration variables `SGX_MODE` and `IAS_MODE`.

These are set by environment variables, and they must be the same for all artifacts,
even those that don't depend directly on SGX. E.g. `mobilecoind` must have the same configuration
as `consensus_service` for Intel Remote Attestation to work, otherwise an error will occur at runtime.

For testing, you should usually use `SGX_MODE=SIM` and `IAS_MODE=DEV`.

## SGX_MODE

`SGX_MODE=SIM` means that the enclaves won't be "real" enclaves -- consensus service will link
to Intel-provided "_sim" versions of the Intel SGX SDK, and the enclave will be loaded approximately
like a shared library being `dlopen`'ed. This means that you will be able to use `gdb` and get
backtraces normally through the enclave code. In this mode, the CPU does not securely compute
measurements of the enclave, and attestation doesn't prove the integrity of the enclave.

`SGX_MODE=HW` means that the real Intel libraries are used, and the enclave is loaded securely.
This mode is required for Intel Remote Attestation to work and provide security.

The clients and servers must all agree about this setting, or attestation will fail.

## IAS_MODE

`IAS_MODE=DEV` means that we will hit the Intel provided "dev endpoints" during remote attestation.
These won't require the real production signing key in connection to the MRENCLAVE measurements.

`IAS_MODE=PROD` means that we will hit the real Intel provided endpoints for remote attestation.

In code, this discrepancy is largely handled by the `attest-net` crate.

The clients and servers must all agree about this setting, or attestation will fail.

#### Building the enclave

For technical reasons, the `consensus_enclave` must be in a separate workspace.
Its build is invoked automatically if needed from the `consensus_service` build.

To reproducibly build the enclave, (get exactly the right MRENCLAVE value), you must build
in the container.
