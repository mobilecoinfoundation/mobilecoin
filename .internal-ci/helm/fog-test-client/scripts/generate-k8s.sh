#!/bin/bash

tmp=/tmp

net="${1}"

case ${net} in
    mc-testnet)
        export CONSENSUS_VALIDATORS="mc://node1.test.mobilecoin.com/,mc://node2.test.mobilecoin.com/,mc://node3.test.mobilecoin.com/"
        export FOG_VIEW="fog-view://fog.test.mobilecoin.com:443"
        export FOG_LEDGER="fog-ledger://fog.test.mobilecoin.com:443"
        export MC_PARTNER="mc"
        export MC_NETWORK="test"
        ;;
    signal-testnet)
        export CONSENSUS_VALIDATORS="mc://node1.test.mobilecoin.com/,mc://node2.test.mobilecoin.com/,mc://node3.test.mobilecoin.com/"
        export FOG_VIEW="fog-view://service.fog.mob.staging.namda.net:443"
        export FOG_LEDGER="fog-ledger://service.fog.mob.staging.namda.net:443"
        export MC_PARTNER="signal"
        export MC_NETWORK="test"
        export CLIENT_AUTH_TOKEN_SECRET="${CLIENT_AUTH_TOKEN_SECRET}"
        ;;
    mc-mainnet)
        export CONSENSUS_VALIDATORS="mc://node1.prod.mobilecoinww.com/,mc://node2.prod.mobilecoinww.com/,mc://node3.prod.mobilecoinww.com/"
        export FOG_VIEW="fog-view://fog.prod.mobilecoinww.com:443"
        export FOG_LEDGER="fog-ledger://fog.prod.mobilecoinww.com:443"
        export MC_PARTNER="mc"
        export MC_NETWORK="prod"
        ;;
    signal-mainnet)
        export CONSENSUS_VALIDATORS="mc://node1.prod.mobilecoinww.com/,mc://node2.prod.mobilecoinww.com/,mc://node3.prod.mobilecoinww.com/"
        export FOG_VIEW="fog-view://service.fog.mob.production.namda.net:443"
        export FOG_LEDGER="fog-ledger://service.fog.mob.production.namda.net:443"
        export MC_PARTNER="signal"
        export MC_NETWORK="prod"
        export CLIENT_AUTH_TOKEN_SECRET="${CLIENT_AUTH_TOKEN_SECRET}"
        ;;
    *)
        echo "Unknown network"
        exit 1
    ;;
esac

net_path="${tmp}/nets/${net}"
measurement_path="${net_path}/measurements"
keys_path="${net_path}/keys"

mkdir -p "${net_path}/k8s"

kubectl create configmap fog-test-client-measurements -o yaml --dry-run=client \
    --from-file "${measurement_path}" \
    | grep -v creationTimestamp > "${net_path}/k8s/fog-test-client-measurements-configMap.yaml"

kubectl create configmap fog-test-client -o yaml --dry-run=client \
    --from-literal=FOG_VIEW="${FOG_VIEW}" \
    --from-literal=FOG_LEDGER="${FOG_LEDGER}" \
    --from-literal=CONSENSUS_VALIDATORS="${CONSENSUS_VALIDATORS}" \
    | grep -v creationTimestamp > "${net_path}/k8s/fog-test-client-configMap.yaml"

kubectl create secret generic fog-test-client-keys -o yaml --dry-run=client \
    --from-file "${keys_path}" \
    | grep -v creationTimestamp > "${net_path}/k8s/fog-test-client-keys-secret.yaml"

if [ -n "${CLIENT_AUTH_TOKEN_SECRET}" ]
then
    kubectl create secret generic fog-client-auth-token -o yaml --dry-run=client \
        --from-literal=token="${CLIENT_AUTH_TOKEN_SECRET}" \
        | grep -v creationTimestamp > "${net_path}/k8s/fog-client-auth-token-secret.yaml"
fi

kubectl create configmap mobilecoin-network -o yaml --dry-run=client \
    --from-literal=network="${MC_NETWORK}" \
    --from-literal=partner="${MC_PARTNER}" \
    | grep -v creationTimestamp > "${net_path}/k8s/mobilecoin-network-configMap.yaml"
