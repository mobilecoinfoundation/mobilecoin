#!/bin/bash
##File to automate local network or release testing using mobilecoind & mobilecoin-d json

## .json file with account keys in form {"view_private_key":"..", "spend_private_key":".."}

## Amount to send
AMOUNT=0.001
## Location of keyfile with view_private_key and spend_private_key
KEYFILE=""
## Length to sleep between sending transactions
SLEEP=1.5
## Curl encoding
enc="Content-Type: application/json"

while [ "$1" != "" ]; do
	case "$1" in
		-a | --amount)
		  shift
		  AMOUNT="$1";;
		-k | --keyfile)
		  shift
		  KEYFILE="$1";;
		-s | --sleep)
		  shift
		  SLEEP="$1";;
		-h)
			echo "Imports key file for an account starts sending test transactions via mobilecoind-json"
			echo "Note: both mobilecoind & mobilecoin-json must both be launched prior to running this script"
			echo "Usage: $(basename $0) [-k | --keyfile]"
			echo ""
			echo "Args:"
			echo "[-a | --amount] amount to send per transaction"
			echo "[-k | --keyfile] location of keyfile with view & spend private keys in format: "
			echo '{"view_private_key":"..", "spend_private_key":".."}'
			echo "[-s | --sleep] period to sleep between sending transactions"
			exit 0
			;;
		*)
			;;
	esac

	shift
done

##Get key material & setup monitor data call
paidkey1=$(cat $KEYFILE | jq .)
mon_data1="{\"account_key\": $paidkey1, \"first_subaddress\": 0, \"num_subaddresses\": 2}"

# Alternatively if desired, import accounts via mnemonic use the following commands
# mnemonic=$(curl localhost:9090/mnemonic -X POST)
# paidkey1=$(curl localhost:9090/account-key-from-mnemonic -d "$mnemonic" -X POST -H "$enc")

#Setup monitor and get it's id and get the account address associated with the keyfile
monitor1=$(curl localhost:9090/monitors -d "$mon_data1" -X POST -H "$enc")
mon_id1=$(echo $monitor1 | jq -r ".monitor_id")
add1=$(curl localhost:9090/monitors/$mon_id1/subaddresses/0/public-address | jq -r ".b58_address_code")

#Setup payment invocations with specified amount (default 0.001)
payrpc1="{\"receiver_b58_address_code\": \"$add1\",\"value\": \"$AMOUNT\"}"
r1=$(curl localhost:9090/monitors/$mon_id1/subaddresses/0/pay-address-code -d "$payrpc1" -X POST -H "$enc")

#Run payments to self every n seconds (default 1.5). More addresses can be added above if desired
while [ true ]
do
	for var in 1
	do
		m="mon_id${var}"
		p="payrpc${var}"
		declare -n mon="$m"
		declare -n pay="$p"
		sleep $SLEEP
		r=$(curl localhost:9090/monitors/$mon/subaddresses/0/pay-address-code -d "$pay" -X POST -H "$enc")
		echo $r
	done
done