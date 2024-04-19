#!/bin/bash
# Copyright (c) 2018-2024 The MobileCoin Foundation
# Scale down a mobilecoin dev environment

set -e
shopt -s inherit_errexit

while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            echo "usage: ${0} [--namespace <namespace>]"
            exit 0
            ;;
        --namespace | -n)
            namespace="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            exit 1
            ;;
    esac
done


if [[ -z "${namespace}" ]]
then
    echo "-n/--namespace is required"
    exit 1
fi

if ! kubectl get namespace "${namespace}" &> /dev/null
then
    echo "namespace ${namespace} does not exist or can't connect to the cluster"
    exit 1
fi

toolbox_cmd()
{
    kubectl exec -n "${namespace}" "${toolbox_pod}" -- /bin/bash -c "$@"
}

# lets find the toolbox pod
toolbox_pod=$(kubectl get pods -n "${namespace}" -l app=toolbox -o jsonpath='{.items[0].metadata.name}')
instance=$(kubectl get pod -n "${namespace}" "${toolbox_pod}" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/instance}')

echo "toolbox pod: ${toolbox_pod}"
echo "ingest instance: ${instance}"

echo "-- Retiring ingest --"
command="RUST_LOG=error fog_ingest_client --uri 'insecure-fog-ingest://${instance}-0.${instance}:3226' retire | jq -r ."
toolbox_cmd "${command}"

echo "-- Running mobilecoind tests to force ingest retire --"
command="/test/mobilecoind-integration-test.sh"
# toolbox_cmd "${command}"

echo "-- Check for retired ingest --"
for i in 0 1
do
    command="RUST_LOG=error fog_ingest_client --uri 'insecure-fog-ingest://${instance}-${i}.${instance}:3226' get-status | jq -r ."
    result=$(toolbox_cmd "${command}")
    mode=$(echo "${result}" | jq -r .mode)

    if [[ "${mode}" == "Active" ]]
    then
        echo "Uh oh, ${instance}-${i}.${instance} ingest not retired"
        exit 1
    fi
done

echo "-- Scaling down fog-ingest --"
kubectl scale sts -n "${namespace}" "${instance}" --replicas=0


echo "-- Scaling down fog-view and fog-ledger --"
# patch the fogshardrangegenerators to reduce the replicas?

for i in fog-view-0 fog-view-1 fog-ledger-0 fog-ledger-1
do
    kubectl patch fogshardrangegenerators.mc.mobilecoin.com -n "${namespace}" "${i}" --type json --patch '[{"op": "replace", "path": "/spec/store/spec/replicas", "value": 0}]'
    kubectl patch fogshardrangegenerators.mc.mobilecoin.com -n "${namespace}" "${i}" --type json --patch '[{"op": "replace", "path": "/spec/router/templates/0/spec/replicas", "value": 0}]'
    kubectl patch fogshardrangegenerators.mc.mobilecoin.com -n "${namespace}" "${i}" --type json --patch '[{"op": "replace", "path": "/spec/router/templates/1/spec/replicas", "value": 0}]'
done

echo "-- Scaling down mobilecoind --"
kubectl scale sts -n "${namespace}" mobilecoind --replicas=0


echo "-- Scaling down consensus --"
echo "wait for fogshardrangegenerators to scale down before scaling down consensus nodes"
echo "the fog controller needs to query the blockchain to take actions on the shards"
sleep 120
for i in 1 2 3
do
    kubectl scale deployment -n "${namespace}" "consensus-node-${i}" --replicas=0
done

echo "-- Done --"
