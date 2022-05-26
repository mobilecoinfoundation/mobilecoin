## mobilecoind-dev-faucet

This is a standalone http server which provides faucet functionality.
* Backed by [mobilecoind](../mobilecoind) -- similar to [mobilecoind-json](../mobilecoind-json), it relays requests to a separate mobilecoind instance, and is itself stateless
* No captcha or rate limiting. This is appropriate for developers running automated tests in a dev cluster.
* TODO: We could make it require an HTTP Authorization header
* Developers can request any token id for testing

### Routes

You may POST to `/`, attaching a json object as the HTTP body:

```
{
    b58_address: <string>,
    token_id: <optional string>
}
```

and the faucet will attempt to send a nominal amount of this token to this address,
or return errors if it cannot. The nominal amount is by default twenty times the minimum
fee for that token.

You may GET to `/status`, and the faucet will respond with a json object:

```
{
    // The balances of the faucet
    balances: { <token_id (string)>:<u64 balance (string)> }
    // The amounts the faucet pays per token id
    faucet_amounts: { <token_id (string)>:<u64 balance (string)> }
    // This address can be paid to replenish the faucet
    b58_address: <string>,
}
```

### Launching

The faucet should be started using a keyfile (which is json containing a mnemonic string or a root entropy).

Options are:

- `--keyfile` - path to the keyfile. this account holds the faucet funds
- `--amount-factor` - An integer `X`. The amount we send when people hit the faucet is `minimum_fee * X`. Default is `X = 20`.
- `--listen-host` - hostname for webserver, default `127.0.0.1`
- `--listen-port` - port for webserver, default `9090`
- `--mobilecoind-uri` - URI for connecting to mobilecoind gRPC, default `insecure-mobilecoind://127.0.0.1:4444/`

### Usage with cURL

Here is some example usage:

Requesting payment:

```
$ curl -s localhost:9090/ -d '{"b58_address": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923"}' -X POST -H 'Content-type: application/json'
{"success":true}
```

```
$ curl -s localhost:9090/ -d '{"b58_address": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923", token_id = "1"}' -X POST -H 'Content-type: application/json'
{"success":true}
```

```
$ curl -s localhost:9090/status
{...}
```
