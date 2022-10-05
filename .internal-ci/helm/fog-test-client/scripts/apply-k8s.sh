#!/bin/bash

tmp=/tmp

net="${1}"

case ${net} in
    mc-testnet)
        namespace="fog-test-client-mc-testnet"
        ;;
    signal-testnet)
        namespace="fog-test-client-signal-testnet"
        ;;
    mc-mainnet)
        namespace="fog-test-client-mc-mainnet"
        ;;
    signal-mainnet)
        namespace="fog-test-client-signal-mainnet"
        ;;
    *)
        echo "Unknown network"
        exit 1
    ;;
esac

kubectl -n "${namespace}" apply -f -d  "${tmp}/nets/${net}/k8s"
