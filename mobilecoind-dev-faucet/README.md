## mobilecoind-dev-faucet

This is a standalone http server which provides faucet functionality.
* Backed by [mobilecoind](../mobilecoind) -- similar to [mobilecoind-json](../mobilecoind-json), it relays requests to a separate mobilecoind instance, and is itself stateless
* No captcha or rate limiting. This is appropriate for developers running automated tests in a dev cluster.
* Any token id can be requested for testing
* TODO: HTTP Authorization headers may be added in the future

### Routes

You may POST to `/`, attaching a json object as the HTTP body:

```
{
    b58_address: <string>,
    token_id: <optional string>
}
```

Any tokenid can be requested and the faucet will attempt to send a nominal amount of
that token to the address specified, or return errors if it cannot. The nominal amount is
by default twenty times the minimum fee for that token. The response will contain a
JSON object, `success` will be `true` if it managed to submit a payment, and there will
be mobilecoind "Receiver Tx receipt" for the submitted transaction. If `success` is `false`
then `err_str` will describe the problem.

GET requests to `/status`, will respond with a json object with the
following information:

```
{
    // The balances of the faucet
    balances: { <token_id (string)>:<u64 balance (string)> }
    // The amounts the faucet pays per token id
    faucet_amounts: { <token_id (string)>:<u64 balance (string)> }
    // The current number of "queued" UTXOs. Each can be used to fill a concurrent request.
    // If a queue is empty then it may take a few seconds for the faucet to refill the queue.
    queue_depths: { <token_id (string)>:<u64 length (string)> }
    // This address can be paid to replenish the faucet
    b58_address: <string>,
}
```

### Launching

The faucet should be started using a keyfile, which is a json formatted file containing a 
mnemonic string or a root entropy for a MobileCoin account.

Required options are:

- `--keyfile` - path to the keyfile with the account mnemonic or entropy. This account holds the faucet funds.

Other options are:
- `--amount-factor` - An integer `X`. The amount we send when people hit the faucet is `minimum_fee * X`. Default is `X = 20`.
- `--listen-host` - hostname for webserver, default `127.0.0.1`
- `--listen-port` - port for webserver, default `9090`
- `--mobilecoind-uri` - URI for connecting to mobilecoind gRPC, default `insecure-mobilecoind://127.0.0.1:4444/`
- `--target-queue-depth` - The number of pre-split transactions the faucet attempts to maintain in its queue. Default is 20.
- `--worker-poll-period-ms` - A lower bound on how often the worker thread wakes up to check in with `mobilecoind`. Default is `100` milliseconds.

### Usage with cURL

Here is some example usage:

Requesting payment:

```
$ curl -s localhost:9090/ -d '{"b58_address": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923"}' -X POST -H 'Content-type: application/json'
{"success":true,"receiver_tx_receipt_list":[{"recipient":{"view_public_key":"86280244d51afed4217ee3dc6288650c27cacc6e4bfb558159f0f8caa38ae542","spend_public_key":"803958b71de5fa7a58d257a0411506e59f77eaff33ee7b7905ac4f9ef68e3c2a","fog_report_url":"","fog_authority_sig":"","fog_report_id":""},"tx_public_key":"880d56bc36411507131098dd404878fb083b6dd5b805c37f736dcfa94d31027d","tx_out_hash":"0fbe90326c255e08b3ee6cbdf626d244ac29bbdab8810163d09513fa1919664f","tombstone":56,"confirmation_number":"027c506b81ad5bd8142382c75f6148f6e5627ad45d2a09110ee9e4ff5a789398"}]}```

```
$ curl -s localhost:9090/ -d '{"b58_address": "c7f04fcd40d093ca6578b13d790df0790c96e94a77815e5052993af1b9d12923", "token_id": "1"}' -X POST -H 'Content-type: application/json'
{"success":false,"err_str":"faucet is depleted"}
```

Getting status:

```
$ curl -s localhost:9090/status
{"b58_address":"5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5","faucet_amounts":{"2":"20480","1":"20480","0":"8000000000"},"balances":{"2":"0","1":"0","0":"12499999997600000000"},"queue_depths":{"1":"0","0":"26","2":"0"}}
```
