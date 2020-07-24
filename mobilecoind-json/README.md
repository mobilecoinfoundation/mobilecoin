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

- `--listen_host` - hostname for webserver, default `127.0.0.1`
- `--listen_port` - port for webserver, default `9090`
- `--mobilecoind_host` - hostname:port for mobilecoind gRPC, default `127.0.0.1:4444`
- `--use_ssl` - connect to mobilecoind using SSL, default is false

### Usage with cURL

#### Generate a new master key
```
$ curl localhost:9090/entropy
{"entropy":"706db549844bc7b5c8328368d4b8276e9aa03a26ac02474d54aa99b7c3369e2e"}
```
#### Add a monitor for a key over a range of subaddress indices
```
$ curl localhost:9090/monitors -d '{"entropy": "706db549844bc7b5c8328368d4b8276e9aa03a26ac02474d54aa99b7c3369e2e", "first_subaddress": 0, "num_subaddresses": 10}' -X POST -H 'Content-Type: application/json'
{"monitor_id":"fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872"}
```

#### Get the status of an existing monitor
```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872
{"first_subaddress":0,"num_subaddresses":10,"first_block":0,"next_block":2068}
```

#### Check the balance for a monitor and subaddress index
```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/0/balance
{"balance":199999999999990}
```
#### Generate a request code for a monitor and subaddress
```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/0/request-code -X POST -d '{"value": 10, "memo": "Please pay me"}' -H 'Content-Type: application/json'
{"request_code":"HUGpTreNKe4ziGAwDNYeW1iayWJgZ4DgiYRk9fw8E7f21PXQRUt4kbFsWBxzcJj12K6atUMuAyRNnwCybw5oJcm6xYXazdZzx4Tc5QuKdFdH2XSuUYM8pgQ1jq2ZBBi"}
```

```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/1/request-code -X POST -d '{}' -H 'Content-Type: application/json'
{"request_code":"2dmFbXtoY78h6K5xsK1NyTHmVGk6oiqBaEYGvJeSLFsCxkL4Ed1vjxEjtwg65QWR8nBdyXnwjyFo6rHEiHmFcsFysjapemAgxWyTda9FVsSFEF"}
```

#### Read all the information in a request code
```
$ curl localhost:9090/read-request/HUGpTreNKe4ziGAwDNYeW1iayWJgZ4DgiYRk9fw8E7f21PXQRUt4kbFsWBxzcJj12K6atUMuAyRNnwCybw5oJcm6xYXazdZzx4Tc5QuKdFdH2XSuUYM8pgQ1jq2ZBBi
{"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263","spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45","fog_url":""},"value":"10","memo":"Please pay me"}
```
This JSON can be passed directly to `transfer` or you can change the amount if desired.

#### Transfer money from a monitor/subaddress to a request code
Using the information in the `read-request`, make a transfer to another address.
```
$ curl localhost:9090//monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/0/transfer -d '{"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263","spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45","fog_url":""},"value":"10","memo":"Please pay me"}' -X POST -H 'Content-Type: application/json'
{"sender_tx_receipt":{"key_images":["dc8a91dbacad97b59e9709379c279a28b3c35262f6744226d15ee87be6bbf132","7e22679d8e3c14ba9c6c45256902e7af8e82644618e65a4589bab268bfde4b61"],"tombstone":2121}, ,"receiver_tx_receipt_list":[{"recipient":{"view_public_key":"f460626a6cefb0bdfc73bb0c3a9c1a303a858f0b1b4ea59b154a1aa8d927af71","spend_public_key":"6a74da2dc6ff116d9278a30a4f8584e9edf165a22faf04a3ac210f219641a92d","fog_report_url":"","fog_authority_fingerprint_sig":"","fog_report_id":""},"tx_public_key":"7060ad50195686ebba591ccfed18ff9536b729d07a00022a21eb21db7e9a266b","tx_out_hash":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112","tombstone":2329,"confirmation_number":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112"}]}
```

This returns receipt information that can be used by the sender to verify their transaction went through and also receipts to give to the receivers
proving that you initiated the transaction

#### Check the status of a transfer with a key image and tombstone block
The return value from `transfer` can be passed directly directly to `get-transfer-status`
```
$ curl localhost:9090/check-transfer-status -d '{"sender_tx_receipt":{"key_images":["dc8a91dbacad97b59e9709379c279a28b3c35262f6744226d15ee87be6bbf132","7e22679d8e3c14ba9c6c45256902e7af8e82644618e65a4589bab268bfde4b61"],"tombstone":2121}}'  -X POST -H 'Content-Type: application/json'
{"status":"verified"}
```

#### Check the status of a transaction from the receiving side and verify confirmation number
The return value from `transfer` includes a list called `receiver_tx_receipt_list`. The appropriate item in the list can be send to the recipient over
a separate channel (e.g. a secure chat application) and they can use it to verify that they were paid by the sender.
```
$ curl localhost:9090/check-receiver-transfer-status -d '{"recipient":{"view_public_key":"f460626a6cefb0bdfc73bb0c3a9c1a303a858f0b1b4ea59b154a1aa8d927af71","spend_public_key":"6a74da2dc6ff116d9278a30a4f8584e9edf165a22faf04a3ac210f219641a92d","fog_report_url":"","fog_authority_fingerprint_sig":"","fog_report_id":""},"tx_public_key":"7060ad50195686ebba591ccfed18ff9536b729d07a00022a21eb21db7e9a266b","tx_out_hash":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112","tombstone":2329,"confirmation_number":"190ec89253bf47a05385b24e5b289a3a31127462aad613da9484f77d03986112"}' -X POST -H 'Content-Type: application/json'
{"status":"verified"}
```

### Ledger status endpoints

#### Ledger totals
```
$ curl localhost:9090/ledger-info
{"block_count":"2280","txo_count":"16809"}
```

#### Counts for a specific block
```
$ curl localhost:9090/block-info/1
{"key_image_count":"1","txo_count":"3"}
```

#### Details about a specific block
```
$ curl localhost:9090/block-details/1
{"block_id":"7b06f8d069f7c169a5a2be51b24331394af832b1453d679e0cca502d3b131bf1","version":0,"parent_id":"e498010ee6a19b4ac9313af43d8274c53d54a1bbc275c06374dbe0095872a6ee","index":"1","cumulative_txo_count":"10003","contents_hash":"c0486e70c50055ecb54ca1f2e8b02fabd1b2322dcd2c133710c3e3149359adec"}
```
