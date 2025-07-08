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
    yellow "Enclave release generating production.json file"

# Create production.json file
cat << EOF > "${PRODUCTION_JSON}"
{
    "consensus": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libconsensus-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/consensus-enclave.css"
    },
    "ingest": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libingest-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/ingest-enclave.css"
    },
    "ledger": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libledger-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/ledger-enclave.css"
    },
    "view": {
        "enclave": "pool/${GIT_COMMIT}/${MRSIGNER}/libview-enclave.signed.so",
        "sigstruct": "pool/${GIT_COMMIT}/${MRSIGNER}/view-enclave.css"
    }
}
EOF

else
    yellow "Downloading artifacts from the latest enclave release"
    # download artifacts from the latest enclave release
    gh release download --clobber \
        --pattern "$(basename "${ENCLAVE_SIGNED_TAR}")" \
        --pattern "$(basename "${MEASUREMENTS_TAR}")" \
        --pattern "$(basename "${PRODUCTION_JSON}")" \
        --pattern "$(basename "${LOG}")" \
        "${ENCLAVE_TAG}" -D "${TMP_DIR}"

    # extract the signed enclaves
    pushd "${TMP_DIR}" >/dev/null
    tar xvzf "${ENCLAVE_SIGNED_TAR}"
    popd >/dev/null
fi


# Create release notes
release_base=$(cat <<EOF
## Changelog

### [Full Chanagelog](https://github.com/mobilecoinfoundation/mobilecoin/blob/${GIT_TAG}/CHANGELOG.md)

EOF
)

release_sgx=$(cat <<EOF
## ${CHAIN_ID}net SGX Measurements

### Signer Measurement

- MRSIGNER: \`${MRSIGNER}\`

### Enclave Measurements (MRENCLAVE)

- libconsensus-enclave.signed.so: \`$(mrenclave "${ENCLAVE_SIGNED_DIR}/libconsensus-enclave.signed.so")\`
- libingest-enclave.signed.so: \`$(mrenclave "${ENCLAVE_SIGNED_DIR}/libingest-enclave.signed.so")\`
- libview-enclave.signed.so: \`$(mrenclave "${ENCLAVE_SIGNED_DIR}/libview-enclave.signed.so")\`
- libledger-enclave.signed.so: \`$(mrenclave "${ENCLAVE_SIGNED_DIR}/libledger-enclave.signed.so")\`

EOF
)

if gh release list --json tagName --jq '.[].tagName' | grep "${GIT_TAG}" >/dev/null 2>&1
then
    yellow "Release ${GIT_TAG} already exists, adding new release notes"

    # download existing release notes
    gh release download "${GIT_TAG}" --clobber --notes "${TMP_DIR}/release-notes.md"
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

