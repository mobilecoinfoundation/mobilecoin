#!/bin/bash
# Copyright 2025 The Sentz Foundation
# Create a release on GitHub using the GitHub CLI.

set -e
set -o pipefail

# location of the script directory
location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
# shellcheck disable=SC1094
source "${location}/.shared_functions"

command -v gh >/dev/null 2>&1 || { red "GitHub CLI (gh) is not installed. Aborting."; exit 1; }

if [[ "${ENCLAVE_RELEASE}" == "true" ]]
then
    yellow "Using local artifact files to create a release"

    check_file "${ENCLAVE_SIGNED_TAR}"
    check_file "${MEASUREMENTS_TAR}"
    check_file "${PRODUCTION_JSON}"
    check_file "${LOG}"
else
    yellow "Downloading artifacts from the latest enclave release"
    # download artifacts from the latest enclave release
    gh release download --clobber \
        --pattern "$(basename "${ENCLAVE_SIGNED_TAR}")" \
        --pattern "$(basename "${MEASUREMENTS_TAR}")" \
        --pattern "$(basename "${PRODUCTION_JSON}")" \
        --pattern "$(basename "${LOG}")" \
        "${ENCLAVE_TAG}" -D "${TMP_DIR}"
fi

yellow "extract the signed enclaves"
pushd "${TMP_DIR}" >/dev/null
tar xvzf "${ENCLAVE_SIGNED_TAR}"
popd >/dev/null

# get mrenclave from production.json
mrenclave_consensus=$(jq -r '.consensus.mrenclave' "${PRODUCTION_JSON}")
mrenclave_ingest=$(jq -r '.ingest.mrenclave' "${PRODUCTION_JSON}")
mrenclave_ledger=$(jq -r '.ledger.mrenclave' "${PRODUCTION_JSON}")
mrenclave_view=$(jq -r '.view.mrenclave' "${PRODUCTION_JSON}")

# Create release notes
release_base=$(cat <<EOF
## Changelog

### [Full Changelog](https://github.com/mobilecoinfoundation/mobilecoin/blob/${GIT_TAG}/CHANGELOG.md)

EOF
)

release_sgx=$(cat <<EOF
## ${CHAIN_ID}net SGX Measurements

### Signer Measurement

- MRSIGNER: \`${MRSIGNER}\`

### Enclave Measurements (MRENCLAVE)

- libconsensus-enclave.signed.so: \`${mrenclave_consensus}\`
- libingest-enclave.signed.so: \`${mrenclave_ingest}\`
- libview-enclave.signed.so: \`${mrenclave_view}\`
- libledger-enclave.signed.so: \`${mrenclave_ledger}\`

EOF
)

if gh release list --json tagName --jq '.[].tagName' | grep "${GIT_TAG}" >/dev/null 2>&1
then
    yellow "Release ${GIT_TAG} already exists, adding new release notes"

    # download existing release notes
    gh release view "${GIT_TAG}" --json body -t '{{.body}}' > "${TMP_DIR}/release-notes.md"
    echo "" >> "${TMP_DIR}/release-notes.md"
    echo "${release_sgx}" >> "${TMP_DIR}/release-notes.md"

    gh release edit "${GIT_TAG}" \
        --prerelease \
        --title "MobileCoin Core (Consensus/Fog) ${GIT_TAG}" \
        --notes-file "${TMP_DIR}/release-notes.md"

    sleep 15
else
    yellow "Creating GitHub Release ${GIT_TAG}"

    # Create release notes
    echo "${release_base}" > "${TMP_DIR}/release-notes.md"
    echo "${release_sgx}" >> "${TMP_DIR}/release-notes.md"

    gh release create "${GIT_TAG}" \
        --prerelease \
        --title "MobileCoin Core (Consensus/Fog) ${GIT_TAG}" \
        --notes-file "${TMP_DIR}/release-notes.md" \

    sleep 15
fi

gh release upload --clobber "${GIT_TAG}" \
    "${ENCLAVE_SIGNED_TAR}" \
    "${MEASUREMENTS_TAR}" \
    "${PRODUCTION_JSON}" \
    "${LOG}" \

