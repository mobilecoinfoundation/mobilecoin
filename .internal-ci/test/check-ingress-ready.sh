#!/bin/bash
# Copyright (c) 2018-2022 The MobileCoin Foundation
#
# check-ingress-ready.sh - loop and wait for valid TLS response on consensus/fog
# ingress endpoints.

set -e

usage()
{
    echo "Usage: $0 --url <url>"
    echo "    --url - fully qualified domain name to wait for up"
}


while (( "$#" ))
do
    case "${1}" in
        --help | -h)
            usage
            exit 0
            ;;
        --url )
            url="${2}"
            shift 2
            ;;
        *)
            echo "${1} unknown option"
            usage
            exit 1
            ;;
    esac
done

counter=0
while ! curl -sSLf -X POST -o /dev/null "${url}"
do
    echo "Waiting for url: ${url}"
    sleep 2

    # exit with error after 10 min of waiting.
    (( counter++ ))
    if [[ counter -gt 300 ]]
    then
        echo "Failed to come up in 10m"
        exit 1
    fi
done
