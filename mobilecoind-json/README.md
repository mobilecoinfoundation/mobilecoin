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
$ curl localhost:9090/create-monitor -d '{"key": "706db549844bc7b5c8328368d4b8276e9aa03a26ac02474d54aa99b7c3369e2e", "start": 0, "number": 10}' -X POST -H 'Content-Type: application/json'
{"monitor_id":"fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872"}
```
#### Check the balance for a monitor and subaddress index
```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/balance/0
{"balance":199999999999990}
```
#### Generate a request code for a monitor and subaddress
```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/request-code/0
{"request_code":"2AgApbiBLx25Rjr771KHEfxoN4CnHbQ642DWubc1uSrJj29P2uuHXPWgjPZyxo6yTBhkjksUxQVyrQmre2eAcoQbtMYvqUHPhb9CBm8fBg7fY3"}
```

```
$ curl localhost:9090/monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/request-code/1
{"request_code":"2dmFbXtoY78h6K5xsK1NyTHmVGk6oiqBaEYGvJeSLFsCxkL4Ed1vjxEjtwg65QWR8nBdyXnwjyFo6rHEiHmFcsFysjapemAgxWyTda9FVsSFEF"}
```

#### Transfer money from a monitor/subaddress to a request code
```
$ curl localhost:9090//monitors/fca4ffa1a1b1faf8ad775d0cf020426ba7f161720403a76126bc8e40550d9872/transfer/0 -d '{"request_code": "2dmFbXtoY78h6K5xsK1NyTHmVGk6oiqBaEYGvJeSLFsCxkL4Ed1vjxEjtwg65QWR8nBdyXnwjyFo6rHEiHmFcsFysjapemAgxWyTda9FVsSFEF", "amount": 12345}' -X POST -H 'Content-Type: application/json'
THmVGk6oiqBaEYGvJeSLFsCxkL4Ed1vjxEjtwg65QWR8nBdyXnwjyFo6rHEiHmFcsFysjapemAgxWyTda9FVsSFEF", "amount": 12345}' -X POST -H 'Content-Type: application/json'
{"key_image":"f8b33cbe8832e9c29bdaef62378c4c1a8590076c2f585069623b1f49e5eaf73f","tombstone":2115}
```
#### Check the status of a transfer with a key image and tombstone block
```
$ curl localhost:9090/status/f8b33cbe8832e9c29bdaef62378c4c1a8590076c2f585069623b1f49e5eaf73f/2115
{"status":"verified"}
```