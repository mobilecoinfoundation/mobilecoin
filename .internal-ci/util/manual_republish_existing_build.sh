#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# This script will grab binaries from an existing build and rebuild
#   the containers/charts with the current configuration.
#   Use with caution.

set -e

usage()
{
cat << USAGE
Usage:
${0} [--pull] [--push] [--images|--image IMG] [--charts|--chart CHART] --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag
    --pull - pull down binaries from source-tag images
    --images - build images
    --charts - build charts
    --push - push images and or charts
    --source-tag - source tag to pull binaries from
    --target-tag - target tag to build images/charts as
    --image "node_hw" - build a specific image
    --chart "consensus" - build a specific chart

example: pull images and extract binaries
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --pull

example: build images for local usage (no push)
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --images

example: build images and push to image repo
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --images --push

example: build charts for local usage (no push)
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --charts

example: build charts and push to harbor for local
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --charts --push

example: do it all pull, build, push
    ${0} --source-tag v1.2.2-dev --target-tag v1.2.3-some-tag --pull --images --charts --push
USAGE
}

is_set()
{
    var_name="${1}"
    if [ -z "${!var_name}" ]
    then
        echo "${var_name} is not set."
        usage
        exit 1
    fi
}

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --source-tag )
            source_tag="${2}"
            shift 2
            ;;
        --target-tag )
            target_tag="${2}"
            shift 2
            ;;
        --pull)
            pull=1
            shift
            ;;
        --push)
            push=1
            shift
            ;;
        --images)
            img=all
            shift
            ;;
        --charts)
            chrt=all
            shift
            ;;
        --chart)
            chrt="${2}"
            shift 2
            ;;
        --image)
            img="${2}"
            shift 2
            ;;
        *)
            echo "ERROR: unknown option"
            usage
            exit 1
            ;;
    esac
done

is_set source_tag
is_set target_tag

source_org=mobilecoin

push_org=mobilecoin
push_tag="${target_tag}"

images=(bootstrap-tools fogingest fog-ledger fogreport fogview go-grpc-gateway mobilecoind node_hw fog-test-client watcher)

charts=(consensus-node consensus-node-config fog-ingest fog-ingest-config fog-services fog-services-config mc-core-common-config mc-core-dev-env-setup mobilecoind watcher)

if [[ -n "${pull}" ]]
then
    for i in "${images[@]}"
    do
        docker rm "${i}" || true
        docker pull "${source_org}/${i}:${source_tag}"
        docker create --name "${i}" "${source_org}/${i}:${source_tag}"
    done

    mkdir -p target/release
    pushd target/release || exit 1
    docker cp "bootstrap-tools:/usr/local/bin/fog-sql-recovery-db-migrations" ./
    docker cp "bootstrap-tools:/usr/local/bin/generate-sample-ledger" ./
    docker cp "bootstrap-tools:/usr/local/bin/sample-keys" ./
    docker cp "bootstrap-tools:/usr/local/bin/fog-distribution" ./
    docker cp "bootstrap-tools:/usr/local/bin/fog_ingest_client" ./
    docker cp "bootstrap-tools:/usr/local/bin/mc-consensus-mint-client" ./
    docker cp "bootstrap-tools:/usr/local/bin/mc-util-seeded-ed25519-key-gen" ./
    docker cp "bootstrap-tools:/usr/local/bin/fog-report-cli" ./
    docker cp "bootstrap-tools:/usr/local/bin/read-pubfile" ./
    docker cp "bootstrap-tools:/usr/local/bin/mc-util-grpc-token-generator" ./
    docker cp "bootstrap-tools:/usr/local/bin/test_client" ./
    docker cp "mobilecoind:/usr/bin/mc-mint-auditor" ./
    docker cp "mobilecoind:/usr/bin/mobilecoind-json" ./
    docker cp "mobilecoind:/enclaves/libingest-enclave.css" ./
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
    docker cp "watcher:/usr/bin/mc-watcher" ./
    popd || exit 1
fi

if [[ "${img}" != "all" ]]
then
    images=(${img})
fi

if [[ -n "${img}" ]]
then
    for i in "${images[@]}"
    do
        echo "-- Building Image ${i}"
        docker build -t "${push_org}/${i}:${push_tag}" \
            --build-arg="GO_BIN_PATH=target/release" \
            --build-arg="REPO_ORG=${push_org}" \
            -f ".internal-ci/docker/Dockerfile.${i}" \
            .
    done

    if [[ -n "${push}" ]]
    then
        for i in "${images[@]}"
        do
            echo "-- Pushing Image ${i}"
            docker push "${push_org}/${i}:${push_tag}"
        done
    fi
fi

if [[ "${chrt}" != "all" ]]
then
    charts=(${chrt})
fi

if [[ -n "${chrt}" ]]
then
    mkdir -p ".tmp/charts"

    for c in "${charts[@]}"
    do
        echo "-- Building Chart ${c}"
        helm dependency update ".internal-ci/helm/${c}"
        helm package ".internal-ci/helm/${c}" \
            -d ".tmp/charts" \
            --app-version="${push_tag}" \
            --version="${push_tag}"
    done

    if [[ -n "${push}" ]]
    then
        for c in "${charts[@]}"
        do
            echo "-- Pushing Chart ${c}"
            # helm repo add mcf-public --username <your-name> \
            #   https://harbor.mobilecoin.com/chartrepo/mobilecoinfoundation-public
            helm cm-push --force ".tmp/charts/${c}-${push_tag}.tgz" mcf-public
        done
    fi
fi
