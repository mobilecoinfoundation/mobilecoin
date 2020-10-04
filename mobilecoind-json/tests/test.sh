#!/bin/sh

# send 11 picoMOB from subaddress 0 to subaddress 1

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
MONITOR_ID_RESPONSE=`curl -s localhost:9090/monitors \
  -d '{"account_key": '"$ACCOUNT_KEY"', "first_subaddress": 0, "num_subaddresses": 10000}' \
  -X POST -H 'Content-Type: application/json'`
FAILED=`echo $MONITOR_ID_RESPONSE | sed -n '/^Failed/p'`
# check if we failed to add the monitor
# e.g. if a monitor with the same keys, but a different subaddress range already exists
if [ -n "$FAILED" ];
  then
    echo "Failed to add monitor!"
    echo $FAILED
    exit 0
fi
MONITOR_ID=`echo $MONITOR_ID_RESPONSE | jq -r '.monitor_id'`

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
      # estimate how much time is left
      DELTA=$((BLOCK_COUNT - MONITOR_NEXT_BLOCK))
      SECONDS_TO_WAIT=$((DELTA/100 + 1))
      MAX_SECONDS_TO_WAIT=30
      if test $SECONDS_TO_WAIT -lt $MAX_SECONDS_TO_WAIT;
        then
          echo "waiting $SECONDS_TO_WAIT seconds..."
          sleep $SECONDS_TO_WAIT
        else
          echo "waiting $MAX_SECONDS_TO_WAIT seconds..."
          sleep $MAX_SECONDS_TO_WAIT
      fi
  fi
done
echo "monitor is ready (next_block = ${MONITOR_NEXT_BLOCK}, block_count = ${BLOCK_COUNT})"

# check balances
SENDER_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/balance \
  | jq -r '.balance'`
RECIPIENT_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/balance \
  | jq -r '.balance'`
BLOCK_COUNT_START=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
echo ""
echo "# before submitting payment: block_count = ${BLOCK_COUNT_START}, sender_balance = ${SENDER_BALANCE}, recipient_balance = ${RECIPIENT_BALANCE}"
echo ""
# get the PublicAddress and the Address Code for the recipient (subaddress 1)
RECIPIENT_PUBLIC_ADDRESS_RESPONSE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/public-address`
RECIPIENT_ADDRESS_CODE=`echo $RECIPIENT_PUBLIC_ADDRESS_RESPONSE |  jq -r '.b58_address_code'`
RECIPIENT_PUBLIC_ADDRESS=`echo $RECIPIENT_PUBLIC_ADDRESS_RESPONSE |  jq 'del(.b58_address_code)' | jq -r '.'`

# # send the payment using the "pay-address-code" API
# echo "sending 11 picoMOB from subaddress 0 to subaddress 1"
# TX_RECEIPTS=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/pay-address-code \
#   -d '{"receiver_b58_address_code": "'"$RECIPIENT_ADDRESS_CODE"'", "value": "11"}' \
#   -X POST -H 'Content-Type: application/json'`


# send the payment by first constructing a TxProposal and then submitting the TxProposal
# this allow us to more easily inspect the transaction's inputs and outputs
echo "# getting all unspent TXOS for subaddress 0"
echo ""
UTXOS_RESPONSE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/utxos`
NUM_UTXOS=`echo ${UTXOS_RESPONSE} | jq -r '.output_list | length'`
echo "found $NUM_UTXOS UTXOS:"
INDEX=0
while test $INDEX -lt $NUM_UTXOS;
do
  UTXO=`echo $UTXOS_RESPONSE | jq '.output_list['"$INDEX"']'`
  UTXO_PUBLIC_KEY=`echo $UTXO | jq -r '.tx_out.public_key'`
  UTXO_KEY_IMAGE=`echo $UTXO | jq -r '.key_image'`
  UTXO_SUBADDRESS=`echo $UTXO | jq -r '.subaddress_index'`
  # we should only find UTXOS for subaddress zero; otherwise show an error
  if [ "$UTXO_SUBADDRESS" != "0" ];
    then
      echo "ERROR: unexpected UTXO subaddress! ($UTXO_SUBADDRESS)"
      exit 0
  fi
  # find each UTXO by its public key in the ledger
  BLOCK=`curl -s localhost:9090/tx-out/${UTXO_PUBLIC_KEY}/block-index | jq -r '.block_index'`
  echo "UTXO[$INDEX]: public_key=$UTXO_PUBLIC_KEY, key_image=$UTXO_KEY_IMAGE, block=$BLOCK"
  INDEX=$((INDEX+1))
done
UTXOS=`echo $UTXOS_RESPONSE | jq -r '.output_list'`
echo ""
# create a payment request code that describes the 11 picoMOB transfer
echo "# creating a request code asking for 11 picoMOB to be sent to subaddress 1"
echo ""
REQUEST_CODE=`curl -s localhost:9090/codes/request \
  -d '{"receiver": '"$RECIPIENT_PUBLIC_ADDRESS"', "value": "11", "memo": ""}' \
  -X POST -H 'Content-Type: application/json' \
  | jq -r '.b58_request_code'`
echo "Payment Request Code:"
echo $REQUEST_CODE
echo ""

# parse the payment request we just constructed
PARSED_REQUEST_CODE=`curl -s localhost:9090/codes/request/${REQUEST_CODE} | jq -r '.'`

echo "# creating the transaction proposal"
TX_PROPOSAL=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/generate-request-code-transaction \
  -d '{"input_list": '"$UTXOS"', "transfer": '"$PARSED_REQUEST_CODE"'}' \
  -X POST -H 'Content-Type: application/json' \
  | jq -r '.tx_proposal'`

# deconstruct and print the proposed TX details
# n.b. the tx hides the true inputs in a ring, so it's easier to get that info from the TxProposal.input_list
TX_PREFIX=`echo $TX_PROPOSAL | jq -r '.tx.prefix'`
INPUTS=`echo $TX_PROPOSAL | jq -r '.input_list'`
NUM_INPUTS=`echo $TX_PROPOSAL | jq -r '.input_list | length'`
OUTPUTS=`echo $TX_PREFIX | jq -r '.outputs'`
NUM_OUTPUTS=`echo $TX_PREFIX | jq -r '.outputs | length'`
FEE=`echo $TX_PREFIX | jq -r '.fee'`
TOMBSTONE_BLOCK=`echo $TX_PREFIX | jq -r '.tombstone_block'`

echo ""
echo "Transaction Proposal:"
echo "FEE:             $FEE pMOB"
echo "TOMBSTONE BLOCK: $TOMBSTONE_BLOCK"
echo "SPENT UTXOS:     $NUM_INPUTS"

INDEX=0
while test $INDEX -lt $NUM_INPUTS;
do
  UTXO=`echo $INPUTS | jq '.['"$INDEX"']'`
  UTXO_PUBLIC_KEY=`echo $UTXO | jq -r '.tx_out.public_key'`
  UTXO_KEY_IMAGE=`echo $UTXO | jq -r '.key_image'`
  UTXO_SUBADDRESS=`echo $UTXO | jq -r '.subaddress_index'`
  # we should only find UTXOS for subaddress zero; otherwise show an error
  if [ "$UTXO_SUBADDRESS" != "0" ];
    then
      echo "ERROR: unexpected UTXO subaddress! ($UTXO_SUBADDRESS)"
      exit 0
  fi
  # find each UTXO we will spend in the ledger
  BLOCK=`curl -s localhost:9090/tx-out/${UTXO_PUBLIC_KEY}/block-index | jq -r '.block_index'`
  echo "[$INDEX]: public_key=$UTXO_PUBLIC_KEY, key_image=$UTXO_KEY_IMAGE, block=$BLOCK"
  INDEX=$((INDEX+1))
done

echo "NEW UTXOS:       $NUM_OUTPUTS"
INDEX=0
while test $INDEX -lt $NUM_OUTPUTS;
do
  UTXO=`echo $OUTPUTS | jq '.['"$INDEX"']'`
  UTXO_PUBLIC_KEY=`echo $UTXO | jq -r '.public_key'`
  echo "[$INDEX]: public_key=$UTXO_PUBLIC_KEY, block=[not in ledger yet]"
  INDEX=$((INDEX+1))
done

echo ""
echo "# submitting the transaction proposal"
echo ""
TX_RECEIPTS=`curl -s localhost:9090/submit-tx \
  -d '{"tx_proposal": '"$TX_PROPOSAL"'}' \
  -X POST -H 'Content-Type: application/json'`

FAILED=`echo $TX_RECEIPTS | sed -n '/^Failed/p'`
if [ -n "$FAILED" ];
  then
    echo "Transaction failed!"
    echo $FAILED
    exit 0
fi

SENDER_TX_RECEIPT=`echo ${TX_RECEIPTS} | jq -r '.sender_tx_receipt'`
RECIPIENT_TX_RECEIPTS=`echo ${TX_RECEIPTS} | jq -r '.receiver_tx_receipt_list'`

# wait for tx to clear
echo "# waiting for the transaction to complete"
echo ""
STATUS="unknown"
while [ "$STATUS" != "verified" ];
do
  echo "waiting 1 second..."
  sleep 1
  STATUS=`curl -s localhost:9090/tx/status-as-sender \
    -d '{"sender_tx_receipt":'"${SENDER_TX_RECEIPT}"', "receiver_tx_receipt_list":[]}' \
    -X POST -H 'Content-Type: application/json' \
    | jq -r '.status'`
  echo "STATUS = ${STATUS}"
done
echo ""
echo "# transaction is complete, checking the transaction receipts"
echo ""
SENDERS_KEY_IMAGES=`echo $SENDER_TX_RECEIPT | jq -r '.key_images'`
NUM_SENDERS_KEY_IMAGES=`echo $SENDER_TX_RECEIPT | jq -r '.key_images | length'`
echo "\"Sender's Receipt\" lists $NUM_SENDERS_KEY_IMAGES spent key images:"
INDEX=0
while test $INDEX -lt $NUM_SENDERS_KEY_IMAGES;
do
  KEY_IMAGE=`echo $SENDERS_KEY_IMAGES | jq '.['"$INDEX"']'`
  echo "[$INDEX]: key_image=$KEY_IMAGE"
  INDEX=$((INDEX+1))
done

echo ""
NUM_RECIPIENT_RECEIPTS=`echo $RECIPIENT_TX_RECEIPTS | jq -r '. | length'`
echo "This payment created $NUM_RECIPIENT_RECEIPTS \"Recipient's Receipts\":"
INDEX=0
while test $INDEX -lt $NUM_RECIPIENT_RECEIPTS;
do
  RECEIPT=`echo $RECIPIENT_TX_RECEIPTS | jq '.['"$INDEX"']'`
  RECEIVER=`echo $RECEIPT | jq '.recipient'`

  # todo: consider fixing API response label to be more consistent (MCC-1895)
  ADDRESS_CODE=`curl -s localhost:9090/codes/address \
    -d '{"receiver": '"$RECEIVER"'}' \
    -X POST -H 'Content-Type: application/json' \
    | jq -r '.b58_code'`
  TRUNCATED_ADDRESS_CODE=`echo $ADDRESS_CODE | cut -c1-16` # truncate address code for display

  PUBLIC_KEY=`echo $RECEIPT | jq -r '.tx_public_key'`
  BLOCK=`curl -s localhost:9090/tx-out/${PUBLIC_KEY}/block-index \
          | jq -r '.block_index'`

  echo "[$INDEX]: public_key=$PUBLIC_KEY, block=$BLOCK, receiver=${TRUNCATED_ADDRESS_CODE}..."
  INDEX=$((INDEX+1))
done

# check balances
SENDER_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/0/balance \
  | jq -r '.balance'`
RECIPIENT_BALANCE=`curl -s localhost:9090/monitors/${MONITOR_ID}/subaddresses/1/balance \
  | jq -r '.balance'`
BLOCK_COUNT_END=`curl -s localhost:9090/ledger/local | jq -r '.block_count'`
echo ""
echo "# after submitting payment: block_count = $BLOCK_COUNT_END, sender_balance = $SENDER_BALANCE, recipient_balance = $RECIPIENT_BALANCE"
echo ""

# go back and check the UTXOs we said we would create in the proposal
echo "# checking that the $NUM_OUTPUTS NEW UTXOS from the TxProposal are now appearing in the ledger:"
INDEX=0
while test $INDEX -lt $NUM_OUTPUTS;
do
  UTXO=`echo $OUTPUTS | jq '.['"$INDEX"']'`
  UTXO_PUBLIC_KEY=`echo $UTXO | jq -r '.public_key'`
  BLOCK=`curl -s localhost:9090/tx-out/${UTXO_PUBLIC_KEY}/block-index | jq -r '.block_index'`
  echo "UTXO[$INDEX]: public_key=$UTXO_PUBLIC_KEY, block=$BLOCK"
  INDEX=$((INDEX+1))
done
echo ""

echo "# waiting 2 seconds to allow for block to finish processing"
sleep 2
echo ""

# now dump the ProcessedTxOut for the block indices of interest
BLOCK_INDEX=$((BLOCK_COUNT_START))
LAST_BLOCK_INDEX=$((BLOCK_COUNT_END - 1))
echo "# looking for processed-block TXO records from block index $BLOCK_INDEX (before payment) to block index $LAST_BLOCK_INDEX (after payment)"
while test $BLOCK_INDEX -le $LAST_BLOCK_INDEX;
do
  # n.b. processed-block using the index which is one less than the block height at BLOCK_INDEX
  PROCESSED_BLOCK=`curl -s localhost:9090/monitors/${MONITOR_ID}/processed-blocks/$BLOCK_INDEX`
  FAILED=`echo $PROCESSED_BLOCK | sed -n '/^Failed/p'`
  if [ -n "$FAILED" ];
    then
      echo "Get processed blocks failed! (try waiting longer for blocks to process)"
      echo $FAILED
      exit 0
  fi

  echo ""
  if [ -z "$PROCESSED_BLOCK" ];
    then
      echo "block ${BLOCK_INDEX} contains 0 processed-block TXO records"
    else
      NUM_TX_OUTS=`echo ${PROCESSED_BLOCK} | jq -r '.tx_outs | length'`
      TX_OUTS=`echo ${PROCESSED_BLOCK} | jq '.tx_outs'`
      echo "block ${BLOCK_INDEX} contains ${NUM_TX_OUTS} processed-block TXO records"
      echo "note that these may be from an earlier transaction -- match public keys and key images to the proposal"
      echo ""
      # print each of the ProcessedTxOutputs we found
      INDEX=0
      while test $INDEX -lt $NUM_TX_OUTS;
      do
        PROCESSED_TXO=`echo $TX_OUTS | jq '.['"$INDEX"']'`
        TXO_MONITOR_ID=`echo $PROCESSED_TXO | jq -r '.monitor_id'`
        TXO_SUBADDRESS=`echo $PROCESSED_TXO | jq -r '.subaddress_index'`
        TXO_PUBLIC_KEY=`echo $PROCESSED_TXO | jq -r '.public_key'`
        TXO_KEY_IMAGE=`echo $PROCESSED_TXO | jq -r '.key_image'`
        TXO_VALUE=`echo $PROCESSED_TXO | jq -r '.value'`
        TXO_DIRECTION=`echo $PROCESSED_TXO | jq -r '.direction'`

        # find each UTXO by its public key in the ledger
        BLOCK=`curl -s localhost:9090/tx-out/${TXO_PUBLIC_KEY}/block-index | jq -r '.block_index'`

        echo "[$INDEX]: public_key=$TXO_PUBLIC_KEY, key_image=$TXO_KEY_IMAGE, block=$BLOCK"
        echo "     value=$TXO_VALUE, direction=$TXO_DIRECTION, subaddress=$TXO_SUBADDRESS"
        INDEX=$((INDEX+1))
      done

  fi
  BLOCK_INDEX=$((BLOCK_INDEX+1))
done

