#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# Script to generate ED25519 keys.
# consensus node message signer keys:
#   echoes the private key in der form, and the public key in pem format.
# consensus node minting:
#   use options to output pem files.

set -e

# we want header or no headers.
while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            echo "usage: ${0} [--public-out <path/to/pub.pem>] [--private-out <path/to/pri.pem>]"
            exit 0
            ;;
        # Path to public key
        --public-out )
            public_out="${2}"
            shift 2
            ;;
        # Path to private key
        --private-out )
            private_out="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            exit 1
            ;;
    esac
done

pri_pem=$(openssl genpkey -algorithm ED25519)
pub_pem=$(echo -n "${pri_pem}" | openssl pkey -pubout)

if [[ -n "${private_out}" ]]
then
    echo -n "${pri_pem}" > "${private_out}"
else
    pri_der=$(echo -n "${pri_pem}" | openssl pkey -outform DER | openssl base64)
    echo "private (DER base64): ${pri_der}"
fi

if [[ -n "${public_out}" ]]
then
    echo -n "${pub_pem}" > "${public_out}"
else
    pub=$(echo -n "${pub_pem}" | grep -v "^-----" | sed 's/+/-/g; s/\//_/g')
    echo "public (PEM w/o headers): ${pub}"
fi
