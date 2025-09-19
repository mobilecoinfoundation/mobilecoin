#!/bin/bash
# Copyright 2025 The Sentz Foundation
# This script builds the enclaves for the release process.

set -e
set -o pipefail

# location of the script directory
location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
# shellcheck disable=SC1094
source "${location}/.shared_functions"

if [[ "${ENCLAVE_RELEASE}" == "false" ]]
then
    red "This is not an enclave release tag. No need to build enclaves. Skip ahead to 03-populate-release.sh."
    exit 1
fi

# Clean and recreate the enclave directory
rm -rf "${ENCLAVE_DIR}"
mkdir -p "${ENCLAVE_DIR}"

yellow "Building enclaves for ${CHAIN_ID}" | tee -a "${LOG}"
echo "------------------------" | tee -a "${LOG}"

yellow "GIT_COMMIT=${GIT_COMMIT}" | tee -a "${LOG}"
yellow "BOOTSTRAP_REVISION=${BOOTSTRAP_REVISION}" | tee -a "${LOG}"
yellow "BOOTSTRAP_DATE=${BOOTSTRAP_DATE}" | tee -a "${LOG}"
yellow "FEE_SPEND_PUBLIC_KEY=${FEE_SPEND_PUBLIC_KEY}" | tee -a "${LOG}"
yellow "FEE_VIEW_PUBLIC_KEY=${FEE_VIEW_PUBLIC_KEY}" | tee -a "${LOG}"
yellow "ENCLAVE_DIR=${ENCLAVE_DIR}" | tee -a "${LOG}"
echo "" | tee -a "${LOG}"
yellow "MINTING_TRUST_ROOT_PUBLIC_KEY_PEM=${MINTING_TRUST_ROOT_PUBLIC_KEY_PEM}" | tee -a "${LOG}"
yellow "Minting Trust Root checksum: $(sha256sum "${MINTING_TRUST_ROOT_PUBLIC_KEY_PEM}" | awk '{print $1}')" | tee -a "${LOG}"

echo "------------------------" | tee -a "${LOG}"
yellow "Cleaning build environment" | tee -a "${LOG}"

pushd "${TOP_LEVEL}" >/dev/null
cargo clean 2>&1 | tee -a "${LOG}"

echo "------------------------" | tee -a "${LOG}"
yellow "Building enclaves" | tee -a "${LOG}"

# Fix git safe directory
git config --global --add safe.directory '*'

cargo build --release --locked \
    -p mc-consensus-enclave-measurement \
    -p mc-fog-ingest-enclave-measurement \
    -p mc-fog-ledger-enclave-measurement \
    -p mc-fog-view-enclave-measurement 2>&1 | tee -a "${LOG}"

echo "------------------------" | tee -a "${LOG}"
yellow "Collecting artifacts in ${ENCLAVE_DIR}" | tee -a "${LOG}"

# collect and package the artifacts
mkdir -p "${ENCLAVE_DIR}"
cp target/release/*-enclave.so "${ENCLAVE_DIR}"
cp target/release/*-enclave.dat "${ENCLAVE_DIR}"

echo "----------------" | tee -a "${LOG}"
yellow "checksums for enclave.so files (sha256sum)" | tee -a "${LOG}"
pushd "${ENCLAVE_DIR}" >/dev/null
for f in *-enclave.so
do
    sha256sum "${f}" | tee -a "${LOG}"
done

echo "----------------" | tee -a "${LOG}"
yellow "Zipping artifacts" | tee -a "${LOG}"

pushd "${TMP_DIR}" >/dev/null
tar -czf "${ENCLAVE_TAR}" "$(basename "${ENCLAVE_DIR}")"

yellow "Enclave tarball created at ${ENCLAVE_TAR}"
