#!/bin/sh

# check for unexpected ProcessedTxOut data when using mobilecoind-json

# usage: ./test.sh <sender master key as 64 hex chars>

# TODO: Check that mobilecoind and mobilecoind-json are both running and start as needed

# set up a monitor for the sender account
ENTROPY=`echo $1 | sed -n '/^[[:xdigit:]]\{64\}/p'`

# check if the master key is valid
if [ -z "$ENTROPY" ];
  then
    echo "You must supply a valid 64 hex character master key for the sender."
    exit 0
fi

ACCOUNT_KEY=`curl -s localhost:9090/entropy/${ENTROPY}`

echo "Sending a test payment for master key = $ENTROPY"

MONITOR_ID=`curl -s localhost:9090/monitors \
  -d '{"account_key": '"$ACCOUNT_KEY"', "first_subaddress": 0, "num_subaddresses": 10}' \
  -X POST -H 'Content-Type: application/json' \
  | jq -r '.monitor_id'`

# wait until the ledger is current

# TODO -- requires MCC-1888

# wait until the monitor is current
BLOCK_COUNT=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
MONITOR_NEXT_BLOCK=`curl -s localhost:9090/monitors/${MONITOR_ID} | jq -r '.next_block'`
echo "Waiting for monitor to be in sync (next_block = ${MONITOR_NEXT_BLOCK}, block_count = ${BLOCK_COUNT})"
while test $MONITOR_NEXT_BLOCK -lt $BLOCK_COUNT;
do
  BLOCK_COUNT=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
  MONITOR_NEXT_BLOCK=`curl -s localhost:9090/monitors/${MONITOR_ID} | jq -r '.next_block'`
  if test $MONITOR_NEXT_BLOCK -lt $BLOCK_COUNT;
    then
      echo "monitor is processing blocks (next_block = ${MONITOR_NEXT_BLOCK}, block_count = ${BLOCK_COUNT})"
      echo "waiting 10 seconds..."
      sleep 10
  fi
done
echo "monitor is ready (next_block = ${MONITOR_NEXT_BLOCK}, block_count = ${BLOCK_COUNT})"

# check balances
SENDER_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/balance \
  | jq -r '.balance'`
RECIPIENT_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/balance \
  | jq -r '.balance'`
BLOCK_COUNT_START=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
echo "before payment: block_count = ${BLOCK_COUNT_START}, sender_balance = ${SENDER_BALANCE}, recipient_balance = ${RECIPIENT_BALANCE}"

# get the public address for the recipient (subaddress 1)
RECIPIENT_ADDRESS_CODE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/public-address \
  | jq -r '.b58_address_code'`

# send the payment
echo "sending 11 picoMOB from subaddress 0 to subaddress 1"
TX_RECIEPTS=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/pay-address-code \
  -d '{"receiver_b58_address_code": "'"$RECIPIENT_ADDRESS_CODE"'", "value": "11"}' \
  -X POST -H 'Content-Type: application/json'`

FAILED_TX=`echo $TX_RECIEPTS | sed -n '/^Failed/p'`
# check if the master key is valid
if [ -n "$FAILED_TX" ];
  then
    echo "Transaction failed!"
    echo $FAILED_TX
    exit 0
fi

SENDER_TX_RECIEPT=`echo ${TX_RECIEPTS} | jq -r '.sender_tx_receipt'`
RECIPIENT_TX_RECIEPT=`echo ${TX_RECIEPTS} | jq -r '.receiver_tx_receipt_list[0]'`

echo "sender's receipt:"
echo `echo $SENDER_TX_RECIEPT | jq -c .`
echo "recipient's receipt:"
echo `echo $RECIPIENT_TX_RECIEPT | jq -c .`

# wait for tx to clear
STATUS="unknown"
while [ "$STATUS" != "verified" ];
do
  STATUS=`curl -s localhost:9090/tx/status-as-sender \
    -d '{"sender_tx_receipt":'"${SENDER_TX_RECIEPT}"', "receiver_tx_receipt_list":[]}' \
    -X POST -H 'Content-Type: application/json' \
    | jq -r '.status'`
  echo "STATUS = ${STATUS}, waiting 1 second"
  sleep 1
done

# check balances
SENDER_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/balance \
  | jq -r '.balance'`
RECIPIENT_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/balance \
  | jq -r '.balance'`
BLOCK_COUNT_END=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
echo "after payment: block_count = $BLOCK_COUNT_END, sender_balance = $SENDER_BALANCE, recipient_balance = $RECIPIENT_BALANCE"

# now dump the ProcessedTxOut for the block indices of interest
BLOCK_INDEX=$((BLOCK_COUNT_START - 1))
LAST_BLOCK_INDEX=$((BLOCK_COUNT_END - 1))
echo "looking for TXOs from block index $BLOCK_INDEX to block index $LAST_BLOCK_INDEX"
while test $BLOCK_INDEX -le $LAST_BLOCK_INDEX;
do
  # n.b. processed-block
  PROCESSED_BLOCK=`curl -s localhost:9090/monitors/${MONITOR_ID}/processed-blocks/$BLOCK_INDEX`
  if [ -z "$PROCESSED_BLOCK" ];
    then
      echo "block ${BLOCK_INDEX} contains 0 processed TXOs for sender master key ${ENTROPY}"
    else
      NUM_TX_OUTS=`echo ${PROCESSED_BLOCK} | jq -r '.tx_outs | length'`
      echo "block ${BLOCK_INDEX} contains ${NUM_TX_OUTS} processed TXOs for sender master key ${ENTROPY}"
      TX_OUTS=`echo ${PROCESSED_BLOCK} | jq '.tx_outs'`
      echo $TX_OUTS
  fi
  BLOCK_INDEX=$((BLOCK_INDEX+1))
done
