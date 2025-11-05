#!/bin/bash
# Copyright 2025 The Sentz Foundation
# This script builds the singed binaries.

set -e
set -o pipefail

# location of the script directory
location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
# shellcheck disable=SC1094
source "${location}/.shared_functions"

if [[ "${ENCLAVE_RELEASE}" == "false" ]]
then
    red "This is not an enclave release tag. No need to build signed enclaves. Skip ahead to 03-populate-release.sh."
    exit 1
fi

# set up paths to enclave files - all these files must exist
export CONSENSUS_ENCLAVE_PUBKEY="${ENCLAVE_DIR}/enclave-public.pem"
export CONSENSUS_ENCLAVE_GENDATA="${ENCLAVE_DIR}/consensus-enclave.dat"
export CONSENSUS_ENCLAVE_SIGNATURE="${ENCLAVE_DIR}/consensus-sig.bin"
export CONSENSUS_ENCLAVE_UNSIGNED="${ENCLAVE_DIR}/libconsensus-enclave.so"

export INGEST_ENCLAVE_PUBKEY="${ENCLAVE_DIR}/enclave-public.pem"
export INGEST_ENCLAVE_GENDATA="${ENCLAVE_DIR}/ingest-enclave.dat"
export INGEST_ENCLAVE_SIGNATURE="${ENCLAVE_DIR}/ingest-sig.bin"
export INGEST_ENCLAVE_UNSIGNED="${ENCLAVE_DIR}/libingest-enclave.so"

export LEDGER_ENCLAVE_PUBKEY="${ENCLAVE_DIR}/enclave-public.pem"
export LEDGER_ENCLAVE_GENDATA="${ENCLAVE_DIR}/ledger-enclave.dat"
export LEDGER_ENCLAVE_SIGNATURE="${ENCLAVE_DIR}/ledger-sig.bin"
export LEDGER_ENCLAVE_UNSIGNED="${ENCLAVE_DIR}/libledger-enclave.so"

export VIEW_ENCLAVE_PUBKEY="${ENCLAVE_DIR}/enclave-public.pem"
export VIEW_ENCLAVE_GENDATA="${ENCLAVE_DIR}/view-enclave.dat"
export VIEW_ENCLAVE_SIGNATURE="${ENCLAVE_DIR}/view-sig.bin"
export VIEW_ENCLAVE_UNSIGNED="${ENCLAVE_DIR}/libview-enclave.so"

yellow "Building signed enclaves for ${CHAIN_ID}" | tee -a "${LOG}"
echo "------------------------" | tee -a "${LOG}"

yellow "GIT_COMMIT=${GIT_COMMIT}" | tee -a "${LOG}"

yellow "CONSENSUS_ENCLAVE_PUBKEY=${CONSENSUS_ENCLAVE_PUBKEY}" | tee -a "${LOG}"
yellow "CONSENSUS_ENCLAVE_GENDATA=${CONSENSUS_ENCLAVE_GENDATA}" | tee -a "${LOG}"
yellow "CONSENSUS_ENCLAVE_SIGNATURE=${CONSENSUS_ENCLAVE_SIGNATURE}" | tee -a "${LOG}"
yellow "CONSENSUS_ENCLAVE_UNSIGNED=${CONSENSUS_ENCLAVE_UNSIGNED}" | tee -a "${LOG}"

yellow "INGEST_ENCLAVE_PUBKEY=${INGEST_ENCLAVE_PUBKEY}" | tee -a "${LOG}"
yellow "INGEST_ENCLAVE_GENDATA=${INGEST_ENCLAVE_GENDATA}" | tee -a "${LOG}"
yellow "INGEST_ENCLAVE_SIGNATURE=${INGEST_ENCLAVE_SIGNATURE}" | tee -a "${LOG}"
yellow "INGEST_ENCLAVE_UNSIGNED=${INGEST_ENCLAVE_UNSIGNED}" | tee -a "${LOG}"

yellow "LEDGER_ENCLAVE_PUBKEY=${LEDGER_ENCLAVE_PUBKEY}" | tee -a "${LOG}"
yellow "LEDGER_ENCLAVE_GENDATA=${LEDGER_ENCLAVE_GENDATA}" | tee -a "${LOG}"
yellow "LEDGER_ENCLAVE_SIGNATURE=${LEDGER_ENCLAVE_SIGNATURE}" | tee -a "${LOG}"
yellow "LEDGER_ENCLAVE_UNSIGNED=${LEDGER_ENCLAVE_UNSIGNED}" | tee -a "${LOG}"

yellow "VIEW_ENCLAVE_PUBKEY=${VIEW_ENCLAVE_PUBKEY}" | tee -a "${LOG}"
yellow "VIEW_ENCLAVE_GENDATA=${VIEW_ENCLAVE_GENDATA}" | tee -a "${LOG}"
yellow "VIEW_ENCLAVE_SIGNATURE=${VIEW_ENCLAVE_SIGNATURE}" | tee -a "${LOG}"
yellow "VIEW_ENCLAVE_UNSIGNED=${VIEW_ENCLAVE_UNSIGNED}" | tee -a "${LOG}"

echo "------------------------" | tee -a "${LOG}"
yellow "Extract artifacts and signing data from tarball" | tee -a "${LOG}"
pushd "${TMP_DIR}" >/dev/null
tar xvzf "${ENCLAVE_TAR}" 2>&1 | tee -a "${LOG}"

echo "------------------------" | tee -a "${LOG}"

check_file "${CONSENSUS_ENCLAVE_PUBKEY}"
check_file "${INGEST_ENCLAVE_PUBKEY}"
check_file "${LEDGER_ENCLAVE_PUBKEY}"
check_file "${CONSENSUS_ENCLAVE_GENDATA}"
check_file "${CONSENSUS_ENCLAVE_SIGNATURE}"
check_file "${CONSENSUS_ENCLAVE_UNSIGNED}"
check_file "${INGEST_ENCLAVE_GENDATA}"
check_file "${INGEST_ENCLAVE_SIGNATURE}"
check_file "${INGEST_ENCLAVE_UNSIGNED}"
check_file "${LEDGER_ENCLAVE_GENDATA}"
check_file "${LEDGER_ENCLAVE_SIGNATURE}"
check_file "${LEDGER_ENCLAVE_UNSIGNED}"
check_file "${VIEW_ENCLAVE_GENDATA}"
check_file "${VIEW_ENCLAVE_SIGNATURE}"
check_file "${VIEW_ENCLAVE_UNSIGNED}"

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
mkdir -p "${ENCLAVE_SIGNED_DIR}"
cp target/release/*.signed.so "${ENCLAVE_SIGNED_DIR}"
mkdir -p "${MEASUREMENTS_DIR}"
cp target/release/*-enclave.css "${MEASUREMENTS_DIR}"

echo "----------------" | tee -a "${LOG}"
yellow "checksums for enclave.so files (sha256sum)" | tee -a "${LOG}"
pushd "${ENCLAVE_DIR}" >/dev/null
for f in *-enclave.so
do
    sha256sum "${f}" | tee -a "${LOG}"
done

echo "----------------" | tee -a "${LOG}"
yellow "checksums for signed.so files (sha256sum)" | tee -a "${LOG}"
pushd "${ENCLAVE_SIGNED_DIR}" >/dev/null
for f in *.signed.so
do
    sha256sum "${f}" | tee -a "${LOG}"
done

echo "----------------" | tee -a "${LOG}"
yellow "Verify enclave and signer are correct:" | tee -a "${LOG}"
for i in *.signed.so
do
  signer_hash=$(mrsigner "${i}")
  enclave_hash=$(mrenclave "${i}")

  if [[ "${MRSIGNER}" == "${signer_hash}" ]]
  then
    echo "${i}"
    echo "  mrsigner:  ${signer_hash}"  | tee -a "${LOG}"
    echo "  mrenclave: ${enclave_hash}" | tee -a "${LOG}"
  else
    red "ERROR: SIGNER_HASH: ${signer_hash} doesn't match expected MRSIGNER:${MRSIGNER}" | tee -a "${LOG}"
    exit 1
  fi
done

echo "----------------" | tee -a "${LOG}"
yellow "Writing ${PRODUCTION_JSON}" | tee -a "${LOG}"
pushd "${TMP_DIR}" >/dev/null

cat << EOF > "${PRODUCTION_JSON}"
{
    "consensus": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libconsensus-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/consensus-enclave.css",
        "mrenclave": "$(mrenclave "${ENCLAVE_SIGNED_DIR}/libconsensus-enclave.signed.so")"
    },
    "ingest": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libingest-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/ingest-enclave.css",
        "mrenclave": "$(mrenclave "${ENCLAVE_SIGNED_DIR}/libingest-enclave.signed.so")"
    },
    "ledger": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libledger-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/ledger-enclave.css",
        "mrenclave": "$(mrenclave "${ENCLAVE_SIGNED_DIR}/libledger-enclave.signed.so")"
    },
    "view": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libview-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/view-enclave.css",
        "mrenclave": "$(mrenclave "${ENCLAVE_SIGNED_DIR}/libview-enclave.signed.so")"
    }
}
EOF

echo "----------------" | tee -a "${LOG}"
yellow "Zipping artifacts" | tee -a "${LOG}"

pushd "${TMP_DIR}" >/dev/null
tar -czf "${ENCLAVE_SIGNED_TAR}" "$(basename "${ENCLAVE_SIGNED_DIR}")"
tar -czf "${MEASUREMENTS_TAR}" "$(basename "${MEASUREMENTS_DIR}")"

yellow "Enclave tarball created at ${ENCLAVE_SIGNED_TAR}"
yellow "Measurements tarball created at ${MEASUREMENTS_TAR}"
