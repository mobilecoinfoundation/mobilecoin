#!/bin/bash

tmp=/tmp

net="${1}"

case ${net} in
    mc-testnet)
        export MC_CONSENSUS="mc://node1.test.mobilecoin.com/,mc://node2.test.mobilecoin.com/,mc://node3.test.mobilecoin.com/"
        export MC_FOG_VIEW="fog-view://fog.test.mobilecoin.com:443"
        export MC_FOG_LEDGER="fog-ledger://fog.test.mobilecoin.com:443"
        ;;
    signal-testnet)
        export MC_CONSENSUS="mc://node1.test.mobilecoin.com/,mc://node2.test.mobilecoin.com/,mc://node3.test.mobilecoin.com/"
        export MC_FOG_VIEW="fog-view://fog.test.mobilecoin.com:443"
        export MC_FOG_LEDGER="fog-ledger://fog.test.mobilecoin.com:443"
        ;;
    mc-mainnet)
        export MC_CONSENSUS="mc://node1.prod.mobilecoinww.com/,mc://node2.prod.mobilecoinww.com/,mc://node3.prod.mobilecoinww.com/"
        export MC_FOG_VIEW="fog-view://fog.prod.mobilecoinww.com:443"
        export MC_FOG_LEDGER="fog-ledger://fog.prod.mobilecoinww.com:443"
        ;;
    signal-mainnet)
        export MC_CONSENSUS="mc://node1.prod.mobilecoinww.com/,mc://node2.prod.mobilecoinww.com/,mc://node3.prod.mobilecoinww.com/"
        export MC_FOG_VIEW="fog-view://fog.prod.mobilecoinww.com:443"
        export MC_FOG_LEDGER="fog-ledger://fog.prod.mobilecoinww.com:443"
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
    --from-literal=MC_FOG_VIEW="${MC_FOG_VIEW}" \
    --from-literal=MC_FOG_LEDGER="${MC_FOG_LEDGER}" \
    --from-literal=MC_CONSENSUS="${MC_CONSENSUS}" \
    --from-literal=MC_CONSENSUS_WAIT="20" \
    | grep -v creationTimestamp > "${net_path}/k8s/fog-test-client-configMap.yaml"

kubectl create secret generic fog-test-client-keys -o yaml --dry-run=client \
    --from-file "${keys_path}" \
    | grep -v creationTimestamp > "${net_path}/k8s/fog-test-client-keys-secret.yaml"
