# Enclave build and release process

### Prerequisites

- Intel or AMD CPU
- docker engine https://docs.docker.com/engine/install/

### Build Unsigned Enclaves

1. Clone the `mobilecoin` repo

    Use the SSH or HTTPS url and clone the repo.

    ```
    git clone git@github.com:mobilecoinfoundation/mobilecoin.git
    OR
    git clone https://github.com/mobilecoinfoundation/mobilecoin.git
    ```

1. Check out the enclave tag you want to build

    This repo uses semver. Enclave updates are considered "breaking" changes. Enclave tags are vX.0.0 tags.  Any minor.patch updates will use the major.0.0 tag for building the enclave.

    ```
    cd mobilecoin
    git checkout v7.0.0
    ```

1. From the root of the `mobilecoin` repo use the `mob` command to start the build container environment.

    ```
    ./mob prompt
    ```

1. From inside the build container: run the build script.

    ```
    tools/release/01-build-enclaves.sh

    Usage:
    01-build-enclaves.sh <--test|--main>
      --test - Set up environment to build testnet enclaves
      --main - Set up environment to build mainnet enclaves
    ```

    To build mainnet use the `--main` option

    ```
    tools/release/01-build-enclaves.sh --main
    ```

    The script will set the appropriate variables, clean the environment, build the enclave.so files and bundle up the results ready for the offline signing process.

1. Compare the results with other builders

    The script output will include checksums of the unsigned enclave files.

    ```
    ----------------
    f48da34620cbf27fd88a16a35255c15d9b16aa8feaebcb115e38502c8d4efa70  libconsensus-enclave.so
    ba9e241e1abc19b12a89acad27a37348275a113a6015e95218551684ea12d7e0  libingest-enclave.so
    f6fcc3174e4568d3ca0b2cff07d41727dece196bfda9b77d4158816c7f179267  libledger-enclave.so
    526d489724696f74f4716296b24c95f945ead68c61291fa56a92afbf9f4f075c  libview-enclave.so
    ----------------
    ```

1. Collect the results for offline signing

    The results and tarball package will be in `.tmp/`. This directory is in the root of the `mobilecoin` repo and is available in the `mob prompt` container and in your parent operating system.

    `chain_id` will be `test` or `main` depending on which option you used when you ran the build script.

    The following files will be generated:

    ```
    .tmp/${chain_id}net-enclaves-${tag}.tar.gz  # tarball package of ${chain_id}net-enclaves-${tag} directory
    .tmp/${chain_id}net-enclaves-${tag}/
      |- build-enclaves.log       # log of the build process
      |- consensus-enclave.dat    # enclave digest file
      |- ingest-enclave.dat       # enclave digest file
      |- ledger-enclave.dat       # enclave digest file
      |- libconsensus-enclave.so  # unsigned enclave
      |- libingest-enclave.so     # unsigned enclave
      |- libledger-enclave.so     # unsigned enclave
      |- libview-enclave.so       # unsigned enclave
      |- view-enclave.dat         # enclave digest file
    ```

### Offline Signing

Copy the `${chain_id}net-enclaves-${tag}.tar.gz` onto a USB drive and transfer the files over to your offline workstation.

Follow KMG process for safe key handling and sign the `.dat` files with `openssl` or an HSM device.

Package original files along with the newly generated `*sig.bin` files and a copy of the enclave signing public key in `.pem` format.

Your tarball should now include the following:

`${chain_id}net-enclaves-${tag}.tar.gz`
```
${chain_id}net-enclaves-${tag}/
  |- build-enclaves.log
  |- consensus-enclave.dat
  |- ingest-enclave.dat
  |- ledger-enclave.dat
  |- view-enclave.dat
  |- libconsensus-enclave.so
  |- libingest-enclave.so
  |- libledger-enclave.so
  |- libview-enclave.so
# new files
  |- enclave-public.pem  # enclave signing public key
  |- consensus-sig.bin   # signature file
  |- ingest-sig.bin      # signature file
  |- ledger-sig.bin      # signature file
  |- view-sig.bin        # signature file
```

Copy the `*sig.bin` and `enclave-public.pem` file back into the `.tmp/${chain_id}net-enclaves-${tag}/` directory and complete the Singed Enclave build.

### Build Signed Enclaves

Place the tarball with the artifacts and signing materials in `.tmp/${chain_id}net-enclaves-${tag}.tar.gz`


The `02-build-signed.sh` script will check to make sure all the files exist in their expected locations.


1. Once the file is in place use the `mob` command in the root of the repo to start the build container environment.

    ```
    ./mob prompt
    ```

1. From inside the build container: run the build script.

    ```
    tools/release/02-build-signed.sh

    Usage:
    01-build-signed.sh <--test|--main>
      --test - Set up environment to build testnet enclaves
      --main - Set up environment to build mainnet enclaves
    ```

    To build mainnet use the `--main` option

    ```
    tools/release/02-build-signed.sh --main
    ```

    The script will set the appropriate variables, clean the environment, and using the previously built unsigned files and `*sig.bin` files build the `*.signed.so` files


1. Compare the results with other builders

    The script output will include checksums of the unsigned enclave files, singed.so files and compare the MRSIGNER values of the build singed measurements with the expected values for the chain-id.

    ```
    ----------------
    checksums for enclave.so files (sha256sum)
    f48da34620cbf27fd88a16a35255c15d9b16aa8feaebcb115e38502c8d4efa70  libconsensus-enclave.so
    ba9e241e1abc19b12a89acad27a37348275a113a6015e95218551684ea12d7e0  libingest-enclave.so
    f6fcc3174e4568d3ca0b2cff07d41727dece196bfda9b77d4158816c7f179267  libledger-enclave.so
    526d489724696f74f4716296b24c95f945ead68c61291fa56a92afbf9f4f075c  libview-enclave.so
    ----------------
    checksums for signed.so files (sha256sum)
    0fb5e9cdc547d5e2a50a0bddd9ff5fb660238bafd8cfce0ff74600478a87a2f4  libconsensus-enclave.signed.so
    842500b513321f799d0b0b471f3e8dd52f5da2e836bf81ebb50de332ecde2177  libingest-enclave.signed.so
    d7c61b0be22225f8e2a2fb1963986de3622944c2caa0f97e6b7558b06246f7c0  libledger-enclave.signed.so
    0ac3c73354e22ed18d92267ebb82e7fbbc164e36f6af46f1ab7694f05fb68ce5  libview-enclave.signed.so
    ----------------
    Verify enclave commit and signer are correct:
    libconsensus-enclave.signed.so
      mrsigner:  bf7fa957a6a94acb588851bc8767e0ca57706c79f4fc2aa6bcb993012c3c386c
      mrenclave: b31e1d01939df31d51855317eed5ab7be4e7c77bf13d51230e38c3f5cb9af332
    libingest-enclave.signed.so
      mrsigner:  bf7fa957a6a94acb588851bc8767e0ca57706c79f4fc2aa6bcb993012c3c386c
      mrenclave: 0578f62dd30d92e31cb8d2df8e84ca216aaf12a5ffdea011042282b53a9e9a7a
    libledger-enclave.signed.so
      mrsigner:  bf7fa957a6a94acb588851bc8767e0ca57706c79f4fc2aa6bcb993012c3c386c
      mrenclave: 3892a844d9ed7dd0f41027a43910935429bd36d82cc8dc1db2aba98ba7929dd1
    libview-enclave.signed.so
      mrsigner:  bf7fa957a6a94acb588851bc8767e0ca57706c79f4fc2aa6bcb993012c3c386c
      mrenclave: 57f5ba050d15d3e9c1cf19222e44a370fb64d8a683c9b33f3d433699ca2d58f2
    ----------------
    ```

1. The process will create two tarball artifacts that will be attached to the GitHub release in the next step
    - `.tmp/${chain_id}net-signed.so-${tag}.tar.gz`
    - `.tmp/${chain_id}net-measurements-${tag}.tar.gz`

### Create GitHub Release

1. Confirm that the tarball artifacts exist
    - `.tmp/${chain_id}net-signed.so-${tag}.tar.gz`
    - `.tmp/${chain_id}net-measurements-${tag}.tar.gz`

1. Run `03-populate-release.sh`

    **This step will not be run in the `mob prompt` container.**

    You will the need `gh` cli tool installed and write access to the mobilecoin repo. https://github.com/cli/cli#installation

    If a release for this tag doesn't exist, this process will create a draft release and upload the build log, measurement, singed enclave artifacts and the "production.json".

### Build Release

Use the GitHub actions `dispatch_workflow` for "(Manual) Build MobileCoin Release".

Select `Run workflow` and pick the Tag you want to build.

The build will check to see if the `.tmp/${chain_id}net-measurements-${tag}.tar.gz` and `${chain_id}net-signed.so-${tag}.tar.gz` tarballs are attached to the GitHub Release for that Tag.

If the tarballs exist and contains all the expected files, the process will build the rest of the release artifacts (binaries, containers, charts) and upload the results to the appropriate repositories.
