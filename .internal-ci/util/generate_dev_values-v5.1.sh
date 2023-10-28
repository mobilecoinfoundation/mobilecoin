#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generates message signer keys and populates other variables.

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# shellcheck source=.shared_functions
source "${location}/.shared_functions"

BASE_PATH=${BASE_PATH:-.tmp}
TOKENS_PATH=${TOKENS_PATH:-"${BASE_PATH}/tokens.signed.json"}

# generate msg signer keys
declare -a signer_keys_pub
declare -a signer_keys_pri

count=1
while [ ${count} -le 3 ]
do
  key=$("${location}/generate_ed25519_keys.sh")
  signer_keys_pub+=("$(echo -n "${key}" | grep public | awk -F': ' '{print $2}')")
  signer_keys_pri+=("$(echo -n "${key}" | grep private | awk -F': ' '{print $2}')")
  ((count++))
done

# Get token config or set empty for older configs.
tokens_signed_json="{}"
if [[ -f "${TOKENS_PATH}" ]]
then
  tokens_signed_json=$(cat "${TOKENS_PATH}")
fi

echo "Get config for network based semver tag" >&2
network=$(get_network_tier "${1}")
case "${network}" in
  test)
    IAS_KEY=${TEST_IAS_KEY}
    IAS_SPID=${TEST_IAS_SPID}
  ;;
  main)
    IAS_KEY=${MAIN_IAS_KEY}
    IAS_SPID=${MAIN_IAS_SPID}
  ;;
  dev)
    IAS_KEY=${DEV_IAS_KEY}
    IAS_SPID=${DEV_IAS_SPID}
  ;;
  *)
    echo "ERROR: Unknown network ${network}"
    exit 1;
  ;;
esac


cat << EOF
global:
  node:
    ledgerDistribution:
      awsAccessKeyId: '${LEDGER_AWS_ACCESS_KEY_ID}'
      awsSecretAccessKey: '${LEDGER_AWS_SECRET_ACCESS_KEY}'

    networkConfig:
      peers:
        1:
          signerPublicKey: ${signer_keys_pub[0]}
        2:
          signerPublicKey: ${signer_keys_pub[1]}
        3:
          signerPublicKey: ${signer_keys_pub[2]}

    tokensConfig:
      tokensSignedJson: |
$(echo -n "${tokens_signed_json}" | sed 's/^/        /')

mcCoreCommonConfig:
  ipinfo:
    token: '${IP_INFO_TOKEN}'
  ias:
    key: '${IAS_KEY}'
    spid: '${IAS_SPID}'
  sentry:
    consensus-sentry-dsn: '${SENTRY_DSN_CONSENSUS}'
    ledger-distribution-sentry-dsn: '${SENTRY_DSN_LEDGER_DISTRIBUTION}'
    fog-report-sentry-dsn: '${SENTRY_DSN_FOG_INGEST}'
    fog-view-sentry-dsn: '${SENTRY_DSN_FOG_VIEW}'
    fog-ledger-sentry-dsn: '${SENTRY_DSN_FOG_LEDGER}'
    fog-ingest-sentry-dsn: '${SENTRY_DSN_FOG_INGEST}'

consensusNodeConfig1:
  node:
    msgSignerKey:
      privateKey: ${signer_keys_pri[0]}

consensusNodeConfig2:
  node:
    msgSignerKey:
      privateKey: ${signer_keys_pri[1]}

consensusNodeConfig3:
  node:
    msgSignerKey:
      privateKey: ${signer_keys_pri[2]}
EOF
