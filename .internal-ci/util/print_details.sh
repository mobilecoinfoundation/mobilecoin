#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Print generated development environment details.
#
cat << EOF
--- Namespace ---

${NAMESPACE}

--- Version ---

${VERSION}

--- Dev Environment Logs ---

https://kibana.logit.io/app/kibana#/discover?_g=()&_a=(columns:!(_source),filters:!(('\$state':(store:appState),meta:(alias:!n,disabled:!f,index:'8ac115c0-aac1-11e8-88ea-0383c11b333c',key:azure.subscription,negate:!f,params:(query:development,type:phrase),type:phrase,value:development),query:(match:(azure.subscription:(query:development,type:phrase)))),('\$state':(store:appState),meta:(alias:!n,disabled:!f,index:'8ac115c0-aac1-11e8-88ea-0383c11b333c',key:kubernetes.namespace_name,negate:!f,params:(query:${NAMESPACE},type:phrase),type:phrase,value:${NAMESPACE}),query:(match:(kubernetes.namespace_name:(query:${NAMESPACE},type:phrase))))),index:'8ac115c0-aac1-11e8-88ea-0383c11b333c',interval:auto,query:(language:kuery,query:''),sort:!('@timestamp',desc))

--- Consensus Endpoints ---

node1.${NAMESPACE}.development.mobilecoin.com
node2.${NAMESPACE}.development.mobilecoin.com
node3.${NAMESPACE}.development.mobilecoin.com
node4.${NAMESPACE}.development.mobilecoin.com
node5.${NAMESPACE}.development.mobilecoin.com

--- Consensus S3 Buckets ---

https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node1.${NAMESPACE}.development.mobilecoin.com/
https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node2.${NAMESPACE}.development.mobilecoin.com/
https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node3.${NAMESPACE}.development.mobilecoin.com/
https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node4.${NAMESPACE}.development.mobilecoin.com/
https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node5.${NAMESPACE}.development.mobilecoin.com/

--- Fog Endpoint ---

fog.${NAMESPACE}.development.mobilecoin.com

--- mobilecoind ---

Connect to mobilecoind API with K8s port forwarding

# mobilecoind grpc
kubectl -n ${NAMESPACE} port-forward service/mobilecoind 3229:3229

# mobilecoind json
kubectl -n ${NAMESPACE} port-forward service/mobilecoind-json 9090:9090

Then Connect to localhost:<port>

--- mobilecoind config options ---

--peer mc://node1.${NAMESPACE}.development.mobilecoin.com:443/ \
--tx-source-url https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node1.${NAMESPACE}.development.mobilecoin.com/ \
--peer mc://node2.${NAMESPACE}.development.mobilecoin.com:443/ \
--tx-source-url https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node2.${NAMESPACE}.development.mobilecoin.com/ \
--peer mc://node3.${NAMESPACE}.development.mobilecoin.com:443/ \
--tx-source-url https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node3.${NAMESPACE}.development.mobilecoin.com/ \
--peer mc://node4.${NAMESPACE}.development.mobilecoin.com:443/ \
--tx-source-url https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node4.${NAMESPACE}.development.mobilecoin.com/ \
--peer mc://node5.${NAMESPACE}.development.mobilecoin.com:443/ \
--tx-source-url https://s3-eu-central-1.amazonaws.com/mobilecoin.eu.development.chain/node5.${NAMESPACE}.development.mobilecoin.com/ \
--poll-interval 1 \
--quorum-set '{ "threshold": 3, "members": [{"args":"node1.${NAMESPACE}.development.mobilecoin.com:443","type":"Node"},{"args":"node2.${NAMESPACE}.development.mobilecoin.com:443","type":"Node"},{"args":"node3.${NAMESPACE}.development.mobilecoin.com:443","type":"Node"},{"args":"node4.${NAMESPACE}.development.mobilecoin.com:443","type":"Node"},{"args":"node5.${NAMESPACE}.development.mobilecoin.com:443","type":"Node"}] }'

--- Get key seeds ---

Seeds for wallets are randomly generated for the environment. You can get the seeds from the secret in the deployment and use sample-keys binary to recreate the keys for testing.

# Set Keys Seeds from k8s secret.
export INITIAL_KEYS_SEED=\$(kubectl -n ${NAMESPACE} get secrets sample-keys-seeds -ojsonpath='{.data.INITIAL_KEYS_SEED}' | base64 -d)

export FOG_KEYS_SEED=\$(kubectl -n ${NAMESPACE} get secrets sample-keys-seeds -ojsonpath='{.data.FOG_KEYS_SEED}' | base64 -d)

export MNEMONIC_KEYS_SEED=\$(kubectl -n ${NAMESPACE} get secrets sample-keys-seeds -ojsonpath='{.data.MNEMONIC_KEYS_SEED}' | base64 -d)

export MNEMONIC_FOG_KEYS_SEED=\$(kubectl -n ${NAMESPACE} get secrets sample-keys-seeds -ojsonpath='{.data.MNEMONIC_FOG_KEYS_SEED}' | base64 -d)

# Copy singing ca cert to file.
kubectl -n ${NAMESPACE} get secrets sample-keys-seeds -ojsonpath='{.data.FOG_REPORT_SIGNING_CA_CERT}' | base64 -d > /tmp/fog_report_signing_ca_cert.pem

# Regenerate keys to /tmp/sample_keys:
docker run -it --rm \
  --env FOG_REPORT_URL="fog://fog.${NAMESPACE}.development.mobilecoin.com" \
  --env FOG_REPORT_SIGNING_CA_CERT="\$(cat fog_report_signing_ca_cert.pem)" \
  --env FOG_KEYS_SEED \
  --env INITIAL_KEYS_SEED \
  --env MNEMONIC_KEYS_SEED \
  --env MNEMONIC_FOG_KEYS_SEED \
  --env FOG_REPORT_SIGNING_CA_CERT_PATH=/tmp/fog_report_signing_ca_cert.pem \
  -v /tmp/fog_report_signing_ca_cert.pem:/tmp/fog_report_signing_ca_cert.pem \
  -v /tmp/sample_data:/tmp/sample_data \
  ${DOCKER_ORG}/bootstrap-tools:${VERSION} /util/generate_origin_data.sh

--- Charts ---

# Add mobilecoin public helm repo
helm repo add mobilecoin-foundation-public ${CHART_REPO}

# Update repo if you already have it installed
helm repo update

# Search repo for helm charts
helm search repo -l --devel --version ${VERSION} mobilecoin-foundation-public

--- Docker Images ---

${DOCKER_ORG}/go-grpc-gateway:${VERSION}
${DOCKER_ORG}/node_hw:${VERSION}
${DOCKER_ORG}/fogingest:${VERSION}
${DOCKER_ORG}/bootstrap-tools:${VERSION}
${DOCKER_ORG}/fogreport:${VERSION}
${DOCKER_ORG}/fogview:${VERSION}
${DOCKER_ORG}/fog-ledger:${VERSION}
${DOCKER_ORG}/mobilecoind:${VERSION}
${DOCKER_ORG}/watcher:${VERSION}
${DOCKER_ORG}/fog-test-client:${VERSION}

--- Binaries ---

All binaries and enclave .css measurements can be found as attached artifacts to this GitHub Actions Run.

EOF
