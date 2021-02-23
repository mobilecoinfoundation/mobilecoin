## mobilecoind-json

This is a standalone executable which provides a simple HTTP JSON API wrapping the [mobilecoind](../mobilecoind) gRPC API.

It should be run alongside `mobilecoind`.

### Launching
Since it is just web server converting JSON requests to gRPC, and it's set up
with the mobilecoind defaults, it can simply be launched with:
```
cargo run
```

Options are:

- `--listen-host` - hostname for webserver, default `127.0.0.1`
- `--listen-port` - port for webserver, default `9090`
- `--mobilecoind-uri` - URI for connecting to mobilecoind gRPC, default `insecure-mobilecoind://127.0.0.1:4444/`

### Usage with cURL

#### Set password for DB

To ensure that the DB stores the account keys at rest, you should call "set-password" via mobilecoind-json on startup. This will set the password for the mobilecoinid-db backend. The password should be derived according to your security needs, for example, with argon2. It needs to be 32 bytes long, so 64 characters hex-encoded.

```
curl -s localhost:9090/set-password -d '{"password": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923"}' -X POST -H 'Content-type: application/json'
{"success":true}
```

The password can also be changed with the same API endpoint. Once a password has been set, future invocations of mobilecoind would need to have it provided in order to unlock (decrypt) the previously-encrypted database.

```
curl -s localhost:9090/unlock-db -d '{"password": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923"}' -X POST -H 'Content-type: application/json'
{"success":true}
```

#### Generate a new master key
```
$ curl localhost:9090/entropy -X POST
{"entropy":"706db549844bc7b5c8328368d4b8276e9aa03a26ac02474d54aa99b7c3369e2e"}
```

#### Generate an account key from entropy
```
$ curl localhost:9090/entropy/706db549844bc7b5c8328368d4b8276e9aa03a26ac02474d54aa99b7c3369e2e

{"view_private_key":"e0d42caf6edd0dc8a762c665ad5682a87e0a7159e60653827be3911af49d2b01",
 "spend_private_key":"e90849e9dcbbb7aa425cfb34ae3978c14e3dfffd18652e7a6a4821cb1557b703"}
```

#### Add a monitor for a key over a range of subaddress indices
```
$ curl localhost:9090/monitors \
  -d '{"account_key": {"view_private_key":"e0d42caf6edd0dc8a762c665ad5682a87e0a7159e60653827be3911af49d2b01", 
       "spend_private_key":"e90849e9dcbbb7aa425cfb34ae3978c14e3dfffd18652e7a6a4821cb1557b703"}, 
       "first_subaddress": 0, "num_subaddresses": 10}' \
  -X POST -H 'Content-Type: application/json'

{"monitor_id":"a0cf8b79c9f8d74eb935ab4eeeb771f3809a408ad47246be47cf40315be9876e"}
```

#### Get the status of an existing monitor
```
$ curl localhost:9090/monitors/<monitor_id>

{"first_subaddress":0,"num_subaddresses":10,"first_block":0,"next_block":2068}
```

#### Remove an existing monitor
```
$ curl -X DELETE localhost:9090/monitors/<monitor_id>

```

#### Check the balance for a monitor and subaddress index
```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/balance

{"balance":199999999999990}
```
#### Get the public address for a monitor and subaddress
```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/public-address

{"view_public_key":"543b376e9d5b949dd8694f065d95a98a89e6f17a20c621621a808605d1904324", 
 "spend_public_key":"58dba855a885dd535dc5180af443abae67c790b860d5adadb4d6a2ecb71abd28",
 "fog_report_url":"","fog_authority_fingerprint_sig":"","fog_report_id":"", 
 "b58_address_code": "7Q6gtA5EqSxkEsqsf5p2j7qEHkA8fBZYNsfuWTZTQaFAqo3FPo8PvhrrUobZfXagrLopzpxqxGBs7Hphwhsc56ryWriPWLCRadhRpnZW6AT"}
```

### Simple payment flow
There are two possible ways to make a payment. The simplest option is to use the intended recipient's `b58_address_code`, which they can get
using the call above. 

#### Initiate a transaction to a b58 public address
This call initiates a transfer to a public address encoded as a b58 string. If the call returns successfully, the transaction has been
submitted to the network. It returns receipts which you can use in calls below to determine if the transaction succeeded.

```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/pay-address-code \
  -d '{"receiver_b58_address_code": "7Q6gtA5EqSxkEsqsf5p2j7qEHkA8fBZYNsfuWTZTQaFAqo3FPo8PvhrrUobZfXagrLopzpxqxGBs7Hphwhsc56ryWriPWLCRadhRpnZW6AT",
       "value": "1"}' \
  -X POST -H 'Content-Type: application/json'

{"sender_tx_receipt":{"key_images":
                      ["dc8a91dbacad97b59e9709379c279a28b3c35262f6744226d15ee87be6bbf132",
                      "7e22679d8e3c14ba9c6c45256902e7af8e82644618e65a4589bab268bfde4b61"],
                      "tombstone":2121},
 "receiver_tx_receipt_list":[
    {"recipient":{"view_public_key":"f460626a6cefb0bdfc73bb0c3a9c1a303a858f0b1b4ea59b154a1aa8d927af71",
                  "spend_public_key":"6a74da2dc6ff116d9278a30a4f8584e9edf165a22faf04a3ac210f219641a92d",
                  "fog_report_url":"", "fog_authority_fingerprint_sig":"", "fog_report_id":""},
    "tx_public_key":"7060ad50195686ebba591ccfed18ff9536b729d07a00022a21eb21db7e9a266b",
    "tx_out_hash":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112",
    "tombstone":2329,
    "confirmation_number":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112"}]}
```

If you would like the change from a used TXO returned to a different subaddress, there is an optional field to do so:
```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/pay-address-code" \
  -d '{"receiver_b58_address_code": "7Q6gtA5EqSxkEsqsf5p2j7qEHkA8fBZYNsfuWTZTQaFAqo3FPo8PvhrrUobZfXagrLopzpxqxGBs7Hphwhsc56ryWriPWLCRadhRpnZW6AT",
       "value": "1",
       "change_subaddress": "2"}' \
  -X POST -H 'Content-Type: application/json'
```

#### Check the status of a transaction with a key image and tombstone block
The return value from `pay-address-code` (and `build-and-submit` below) can be passed directly to `status-as-sender`
```
$ curl localhost:9090/tx/status-as-sender \
  -d '{"sender_tx_receipt":{"key_images":
        ["dc8a91dbacad97b59e9709379c279a28b3c35262f6744226d15ee87be6bbf132",
         "7e22679d8e3c14ba9c6c45256902e7af8e82644618e65a4589bab268bfde4b61"],
       "tombstone":2121}, "receiver_tx_receipt_list":[]}' \
  -X POST -H 'Content-Type: application/json'

{"status":"verified"}
```

#### Check the status of a transaction from the receiving side and verify confirmation number
The return value from `pay-address-code` includes a list called `receiver_tx_receipt_list`. The appropriate item in
the list can be send to the recipient over a separate channel (e.g. a secure chat application) and they can use it to
verify that they were paid by the sender.
```
$ curl localhost:9090/monitors/<monitor_id>/tx-status-as-receiver \
  -d '{"recipient":{"view_public_key":"f460626a6cefb0bdfc73bb0c3a9c1a303a858f0b1b4ea59b154a1aa8d927af71",
                    "spend_public_key":"6a74da2dc6ff116d9278a30a4f8584e9edf165a22faf04a3ac210f219641a92d",
                    "fog_report_url":"", "fog_authority_fingerprint_sig":"", "fog_report_id":""},
        "tx_public_key":"7060ad50195686ebba591ccfed18ff9536b729d07a00022a21eb21db7e9a266b",
        "tx_out_hash":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112",
        "tombstone":2329,
        "confirmation_number":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112"}' \
  -X POST -H 'Content-Type: application/json'

{"status":"verified"}
```

### Request code payment flow
Request codes combine a public address with an requested payment value and a memo field. They can also be encoded in b58 and shared.
A potential sender interpreting a b58 request code must first read the information which allows them to verify or modify the value.

#### Generate a request code from a public address and optional other information
```
$ curl localhost:9090/codes/request \
  -d '{"receiver": {"view_public_key":"543b376e9d5b949dd8694f065d95a98a89e6f17a20c621621a808605d1904324",
                    "spend_public_key":"58dba855a885dd535dc5180af443abae67c790b860d5adadb4d6a2ecb71abd28",
                    "fog_report_url":"","fog_authority_fingerprint_sig":"","fog_report_id":""},
        "value": "10", "memo": "Please pay me"}' \
  -X POST -H 'Content-Type: application/json'

{"b58_request_code":"ufTwqVqF2rXmFVBZ1CWWS3ntdajVZGfZ5A2YZqAwhVnaVYrFpS9Z8iAg44CBGDeyjFDX8Hj4W7ZzArBn1xSp9wu8NriqQAogN8fUybKmoWgaz92kT4M7fbjRYKZmoY8"}
```

#### Read all the information in a request code
```
$ curl localhost:9090/codes/request/HUGpTreNKe4ziGAwDNYeW1iayWJgZ4DgiYRk9fw8E7f21PXQRUt4kbFsWBxzcJj12K6atUMuAyRNnwCybw5oJcm6xYXazdZzx4Tc5QuKdFdH2XSuUYM8pgQ1jq2ZBBi

{"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263",
             "spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45",
             "fog_url":""},
 "value":"10","memo":"Please pay me"}
```
This JSON can be passed directly to `build-and-submit` or you can change the amount if desired.

#### Build and submit a payment from a monitor/subaddress to a request code
Using the information in the `read-request`, creates and submits a transaction. If this succeeds, funds will be transferred.
```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/build-and-submit \
  -d '{"request_data":
          {"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263",
                       "spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45",
                       "fog_url":""},
        "value":"10","memo":"Please pay me"}}' \
  -X POST -H 'Content-Type: application/json'

{"sender_tx_receipt":{"key_images":
                      ["dc8a91dbacad97b59e9709379c279a28b3c35262f6744226d15ee87be6bbf132",
                      "7e22679d8e3c14ba9c6c45256902e7af8e82644618e65a4589bab268bfde4b61"],
                      "tombstone":2121},
 "receiver_tx_receipt_list":[
    {"recipient":{"view_public_key":"f460626a6cefb0bdfc73bb0c3a9c1a303a858f0b1b4ea59b154a1aa8d927af71",
                  "spend_public_key":"6a74da2dc6ff116d9278a30a4f8584e9edf165a22faf04a3ac210f219641a92d",
                  "fog_report_url":"", "fog_authority_fingerprint_sig":"", "fog_report_id":""},
    "tx_public_key":"7060ad50195686ebba591ccfed18ff9536b729d07a00022a21eb21db7e9a266b",
    "tx_out_hash":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112",
    "tombstone":2329,
    "confirmation_number":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112"}]}
```

This returns receipt information that can be used by the sender to verify their transaction went through and also receipts to give to the receivers
proving that you initiated the transaction. See *Check the status of a transaction* above.

#### Get block index by a tx output public key.

$ curl localhost:9090/tx-out/c853d6c33f5801941a312a5f876fa1e1379bb624a3acbdce5a64506522c6c223/block-index

{"block_index":"1298"}

### Ledger status endpoints

#### Ledger totals
```
$ curl localhost:9090/ledger/local

{"block_count":"2280","txo_count":"16809"}
```

#### Counts for a specific block
```
$ curl localhost:9090/ledger/blocks/1/header

{"key_image_count":"1","txo_count":"3"}
```

#### Details about a specific block
```
$ curl localhost:9090/ledger/blocks/1

{"block_id":"7b06f8d069f7c169a5a2be51b24331394af832b1453d679e0cca502d3b131bf1",
 "version":0,"parent_id":"e498010ee6a19b4ac9313af43d8274c53d54a1bbc275c06374dbe0095872a6ee",
 "index":"1","cumulative_txo_count":"10003",
 "contents_hash":"c0486e70c50055ecb54ca1f2e8b02fabd1b2322dcd2c133710c3e3149359adec"}
```

### Offline Transactions

First, run the mobilecoind binary in offline mode, and run mobilecoind-json, both on the airgapped machine.

#### Get UnspentTxos
On the airgapped machine, get the utxos in the local ledger.

```
$ curl localhost:9090/monitors/<monitor_id>/subaddresses/<subaddress>/utxos
```

### GenerateTx
On the airgapped machine, generate a tx proposal.

```
$ curl localhost:9090/monitors/<monitor-id>/subaddresses/<subaddress>/generate-tx \
  -d ‘{“input_list”: [<paste output of utxos response>], “transfer”: ‘$(cat request_code.json)’}’ \ 
  -X POST -H ‘Content-Type: application/json’ > tx_proposal.json
```

### Submit Propsoal
Copy the tx_proposal.json to the internet connected machine, and submit.

```
$ curl localhost:9090/submit -d $(cat tx_propsoal.json) -X POST -H 'Content-Type: application/json'
```
