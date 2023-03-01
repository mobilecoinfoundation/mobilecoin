#!/bin/bash

tmp=/tmp

net="${1}"

case ${net} in
    mc-testnet)
        namespace="fog-test-client-mc-test"
        ;;
    signal-testnet)
        namespace="fog-test-client-signal-test"
        ;;
    mc-mainnet)
        namespace="fog-test-client-mc-main"
        ;;
    signal-mainnet)
        namespace="fog-test-client-signal-main"
        ;;
    *)
        echo "Unknown network"
        exit 1
    ;;
esac

kubectl -n "${namespace}" apply -f -d  "${tmp}/nets/${net}/k8s"
