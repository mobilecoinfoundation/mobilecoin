#!/bin/bash

set -e

# Paths
location=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
tmp=/tmp

# Nets
all_nets="mc-mainnet mc-testnet signal-testnet signal-mainnet"
test_nets="mc-testnet signal-testnet"
prod_nets="mc-mainnet signal-mainnet"
signal_nets="signal-mainnet signal-testnet"

# Vaults
wallet_vault="Fog-Test-Client Wallets"

echo "---- Check to see if you're logged into 1Password and get Wallet Vault"
vault_items=$(op list items --vault "${wallet_vault}")

echo "---- Setup keys and measurements directories"
for n in ${all_nets}
do
    mkdir -p "${tmp}/nets/${n}/keys"
    mkdir -p "${tmp}/nets/${n}/measurements"
done

echo "---- Download testnet sigstructs"
for n in ${test_nets}
do
    export NETWORK=test.mobilecoin.com

    pushd "${tmp}/nets/${n}/measurements" || exit 1
    "${location}/download_sigstruct.sh"
    popd || exit 1
done

echo "---- Download mainnet sigstructs"
for n in ${prod_nets}
do
    export NETWORK=prod.mobilecoin.com

    pushd "${tmp}/nets/${n}/measurements" || exit 1
    "${location}/download_sigstruct.sh"
    popd || exit 1
done


echo "---- Populate keys from 1pass vault"
for n in ${all_nets}
do
    # get uuid for vault item that matches the network
    uuid=$(echo "${vault_items}" |jq -r ".[] | select(.overview.title | match(\"${n}/fog-test-client\")).uuid")
    # get item details for that uuid
    item=$(op get item "${uuid}")
    # list the fields for item - this contains the filenames (n) and contents (v)
    fields=$(echo "${item}" | jq -r '.details.sections[0].fields[].n')
    
    # write values for each file
    for f in ${fields}
    do
        name=$(echo "${item}" | jq -r ".details.sections[0].fields[] | select(.n == \"${f}\").t")
        value=$(echo "${item}" | jq -r ".details.sections[0].fields[] | select(.n == \"${f}\").v")

        [ -n "${DEBUG}" ] && echo "DEBUG: Writing ${tmp}/nets/${n}/keys/${name}"
        # .pub files are binary need to base64 decode values.
        if [[ $name =~ \.pub$ ]]
        then
            [ -n "${DEBUG}" ] && echo "DEBUG: base64 decode"
            echo -n "${value}" | base64 -i -d -w0 > "${tmp}/nets/${n}/keys/${name}"
        else
            echo "${value}" > "${tmp}/nets/${n}/keys/${name}"
        fi
    done
done

echo "---- Get fog-client-auth-token-secrets"
for n in ${signal_nets}
do
    # get uuid for fog-client-auth-secret by network
    uuid=$(echo "${vault_items}" |jq -r ".[] | select(.overview.title | match(\"${n}/fog-client-auth-token-secret\")).uuid")
    # get item details for uuid
    item=$(op get item "${uuid}")
    # get password for in item
    value=$(echo "${item}" | jq -r '.details.fields[] | select(.name=="password").value')

    # write value to file
    echo -n "${value}" > "${tmp}/nets/${n}/fog-client-auth-token-secret"
done

echo "---- Generate k8s objects"
for n in ${all_nets}
do
    if [[ ${n} =~ ^signal ]]
    then
        CLIENT_AUTH_TOKEN_SECRET=$(cat "${tmp}/nets/${n}/fog-client-auth-token-secret")
        export CLIENT_AUTH_TOKEN_SECRET
    fi

    "${location}/generate-k8s.sh" "${n}"
    unset CLIENT_AUTH_TOKEN_SECRET
done
