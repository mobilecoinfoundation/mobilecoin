#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# This script will grab binaries from an existing build are rebuild
#   the containers/charts with the current configuration.

#   Use with caution.

set -e
set -x

source_tag=demo-v20220307170316

push_org=jgreat
push_tag=1.1.3-dev

images=(bootstrap-tools fogingest fog-ledger fogreport fogview go-grpc-gateway mobilecoind node_hw fog-test-client)

charts=(consensus-node consensus-node-config fog-ingest fog-ingest-config fog-services fog-services-config mc-core-common-config mc-core-dev-env-setup mobilecoind )

for i in "${images[@]}"
do
    docker rm "${i}" || true
    docker create --name "${i}" "mobilecoin/${i}:${source_tag}"
done

mkdir -p target/release
pushd target/release || exit 1
docker cp "bootstrap-tools:/usr/local/bin/fog-sql-recovery-db-migrations" ./
docker cp "bootstrap-tools:/usr/local/bin/generate-sample-ledger" ./
docker cp "bootstrap-tools:/usr/local/bin/sample-keys" ./
docker cp "bootstrap-tools:/usr/local/bin/fog-distribution" ./
docker cp "bootstrap-tools:/usr/local/bin/fog_ingest_client" ./
docker cp "fog-ledger:/usr/bin/libledger-enclave.signed.so" ./
docker cp "fog-ledger:/usr/bin/ledger_server" ./
docker cp "fog-ledger:/usr/bin/mobilecoind" ./
docker cp "fog-ledger:/usr/bin/mc-admin-http-gateway" ./
docker cp "fog-ledger:/usr/bin/mc-ledger-migration" ./
docker cp "fog-ledger:/usr/bin/mc-util-grpc-admin-tool" ./
docker cp "fogingest:/usr/bin/libingest-enclave.signed.so" ./
docker cp "fogingest:/usr/bin/fog_ingest_server" ./
docker cp "fogreport:/usr/bin/report_server" ./
docker cp "fogview:/usr/bin/libview-enclave.signed.so" ./
docker cp "fogview:/usr/bin/fog_view_server" ./
docker cp "go-grpc-gateway:/usr/bin/go-grpc-gateway" ./grpc-proxy
docker cp "node_hw:/usr/bin/consensus-service" ./
docker cp "node_hw:/usr/bin/ledger-distribution" ./
docker cp "node_hw:/usr/bin/ledger-from-archive" ./
docker cp "node_hw:/usr/bin/libconsensus-enclave.signed.so" ./
docker cp "fog-test-client:/usr/local/bin/test_client" ./
docker cp "fog-test-client:/usr/local/bin/mc-util-grpc-token-generator" ./
popd || exit 1

for i in "${images[@]}"
do
    docker build -t "${push_org}/${i}:${push_tag}" \
        --build-arg="GO_BIN_PATH=target/release" \
        --build-arg="REPO_ORG=${push_org}" \
        -f ".internal-ci/docker/Dockerfile.${i}" \
        ./
done

for i in "${images[@]}"
do
    docker push "${push_org}/${i}:${push_tag}"
done

mkdir -p ".tmp/charts"

for c in "${charts[@]}"
do
    helm dependency update ".internal-ci/helm/${c}"
    helm package ".internal-ci/helm/${c}" \
        -d ".tmp/charts" \
        --app-version="${push_tag}" \
        --version="${push_tag}"
done

for c in "${charts[@]}"
do
    helm s3 push --relative --force ".tmp/charts/${c}-${push_tag}.tgz" mobilecoin
done
