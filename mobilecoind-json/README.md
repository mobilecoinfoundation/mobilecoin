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
{"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263","spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45","fog_fqdn":""},"value":"10","memo":"Please pay me"}
```
This JSON can be passed directly to `transfer` or you can change the amount if desired.

#### Transfer money from a monitor/subaddress to a request code
Using the information in the `read-request`, make a transfer to another address.
```
$ curl localhost:9090//monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/0/transfer -d '{"receiver":{"view_public_key":"40f884563ff10fb1b37b589036db9abbf1ab7afcf88f17a4ea6ec0077e883263","spend_public_key":"ecf9f2fdb8714afd16446d530cf27f2775d9e356e17a6bba8ad395d16d1bbd45","fog_fqdn":""},"value":"10","memo":"Please pay me"}' -X POST -H 'Content-Type: application/json'
{"key_image":"1e9ed007fd05b8b2830af652e91be042bbff6d013eb6d5101001e83758a0c94d","tombstone":2118}
```
#### Check the status of a transfer with a key image and tombstone block
The return value from `transfer` can be passed directly directly to `get-transfer-status`
```
$ curl localhost:9090/check-transfer-status -d '{"key_image":"1e9ed007fd05b8b2830af652e91be042bbff6d013eb6d5101001e83758a0c94d","tombstone":2118}' -X POST -H 'Content-Type: application/json'
{"status":"verified"}
```