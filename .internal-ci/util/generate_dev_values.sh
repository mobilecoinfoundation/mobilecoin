#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Generates message signer keys and populates other variables.

location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
# shellcheck disable=SC1091 # Shellcheck doesn't like variable source path.
. "${location}/source.sh"

# generate msg signer keys
declare -a signer_keys_pub
declare -a signer_keys_pri

count=1
while [ ${count} -le 5 ]
do
  key=$("${location}/generate_msg_signer_keys.sh")
  signer_keys_pub+=("$(echo -n "${key}" | grep public | awk '{print $2}')")
  signer_keys_pri+=("$(echo -n "${key}" | grep private | awk '{print $2}')")
  ((count++))
done

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
        4:
          signerPublicKey: ${signer_keys_pub[3]}
        5:
          signerPublicKey: ${signer_keys_pub[4]}

mcCoreCommonConfig:
  ias:
    key: '${IAS_KEY}'
    spid: '${IAS_SPID}'
  clientAuth:
    token: '${CLIENT_AUTH_TOKEN}'
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

consensusNodeConfig4:
  node:
    msgSignerKey:
      privateKey: ${signer_keys_pri[3]}

consensusNodeConfig5:
  node:
    msgSignerKey:
      privateKey: ${signer_keys_pri[4]}

fogServicesConfig:
  fogReport:
    signingCert:
      key: |-
$(echo -n "${FOG_REPORT_SIGNING_CERT_KEY}" | sed 's/^/        /g')
      crt: |-
$(echo -n "${FOG_REPORT_SIGNING_CERT}" | sed 's/^/        /g')

EOF
