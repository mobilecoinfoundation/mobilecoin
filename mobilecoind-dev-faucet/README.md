## mobilecoind-dev-faucet

This is a standalone http server which provides faucet functionality.
* Backed by [mobilecoind](../mobilecoind) -- similar to [mobilecoind-json](../mobilecoind-json), it relays requests to a separate mobilecoind instance, and is itself stateless
* No captcha or rate limiting. This is appropriate for developers running automated tests in a dev cluster.
* Any token id can be requested for testing
* TODO: HTTP Authorization headers may be added in the future

The faucet also supports network load-testing functionality called "slam".
The purpose of a slam test is to submit Txs in parallel to the network as fast as possible.

### Routes

You may POST to `/`, attaching a json object as the HTTP body:

```
{
    b58_address: <string>,
    token_id: <optional string>
}
```

Any token can be requested and the faucet will attempt to send a nominal amount of
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
    // A progress report for slam if any is in-progress
    slam_status: <string>,

}
```

POST requests to `/slam` will trigger a "slam" which is a network load test. Many threads
are spawned which submit Txs in parallel to the network as rapidly as possible, saturating it.

Optionally, a json config object may be attached to adjust the parameters, overriding the defaults:

```
{
    /// Target num txs to submit in the slam.
    /// Note: Ideally this is not more than the target_queue_depth number,
    /// or we will have to split more Txs before we can slam which will take some time.
    /// Default is 500.
    target_num_tx: <number>,
    /// Number of threads to create during slamming
    /// Default is 30.
    num_threads: <number>,
    /// Number of retries to use when submitting Txs
    /// Default is 30.
    retries: <number>,
    /// How much ahead of the network to set the tombstone block
    /// Default is 20.
    tombstone_offset: <number>,
    /// Which consensus endpoints to submit transactions to
    consensus_uris: <list of strings>,
}
```

This post will not return a response until the slam is finished. The response will
contain a report of how many Tx's were prepared and submitted successfully and how long
each step took.

POST requests to `/cancel_slam` will cancel an in-progress slam.

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
- `--target-queue-depth` - The number of pre-split transactions the faucet attempts to maintain in its queue. Default is 500.
- `--worker-poll-period-ms` - A lower bound on how often the worker thread wakes up to check in with `mobilecoind`. Default is `100` milliseconds.

### Usage with cURL

It is relatively straightforward to test the faucet locally using the `tools/local_network.py` script. First simply follow those instructions to start a local network from your shell.

(depending on if you run in docker or not your ledger base may be different)

```
$ cargo build --release
$ ./tools/local_network/bootstrap.sh
$ export LEDGER_BASE=/tmp/mobilenode/target/sample_data/ledger
$ export MC_LOG=info
$ ./tools/local_network/local_network.py --network-type dense5 --skip-build &
```

Then, start a faucet and set it to also work in the background:

```
$ ./target/release/mobilecoind-dev-faucet --keyfile "$LEDGER_BASE/../keys/account_keys_0.json" &
```

You should expect to see traffic on the network as soon as you launch this. This is the worker thread
splitting off 15 Utxos at a time. At some point it reaches the target queue depth and stops, then the
network will be quiet.

You can test the faucet with curl, here are some examples:

#### Getting the status

```
$ curl -s localhost:9090/status
{"success":true,"b58_address":"5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5","faucet_payout_amounts":{"1":"20480","0":"8000000000","2":"20480"},"balances":{"2":"0","0":"12499999970400000000","1":"0"},"queue_depths":{"0":"525","1":"0","2":"0"},"slam_status":null}```
```

#### Requesting payment

```
curl -s localhost:9090/ -d '{"b58_address": "5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5"}' -X POST
{"success":true,"receiver_tx_receipt_list":[{"recipient":{"view_public_key":"86280244d51afed4217ee3dc6288650c27cacc6e4bfb558159f0f8caa38ae542","spend_public_key":"803958b71de5fa7a58d257a0411506e59f77eaff33ee7b7905ac4f9ef68e3c2a","fog_report_url":"","fog_authority_sig":"","fog_report_id":""},"tx_public_key":"f82a02524551f6a10db81a016c8aa5a666432d659e2841ccdb563b062aad5157","tx_out_hash":"6581ce42992ae9072e7054f6b1a5f414fab7f328e53dcf128551b73666e2fb64","tombstone":106,"confirmation_number":"f46be1aff74c8973b773094ba8f1afc015867c9c40998e6a65fc0d56c9a114e7"}]}
```

#### Requesting payment in an alternate token id

```
curl -s localhost:9090/ -d '{"b58_address": "5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5", "token_id": "1"}' -X POST
{"success":false,"err_str":"Funds are depleted"}
```

#### Requesting 25 payments

```
$ seq 25 | xargs -I{} curl -s localhost:9090/ -d '{"b58_address": "5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5"}' -X POST && echo {}
```

If running a local network, you should expect to see some logs that show large blocks as a result of this:

```
2022-06-13 21:07:50.409629641 UTC INFO Processed 29 utxos and 29 key images in block 53 for monitor id 1765672a36b1a18aa038c301bafa89a7f40c2e0dedf48e96ccab3bb730bb32cf, mc.app: mobilecoind, mc.module: mc_mobilecoind::database, mc.src: mobilecoind/src/database.rs:307
```

#### Triggering a slam

A basic slam request looks like this:

```
curl -s localhost:9090/slam -X POST
```

You may get this error:

```
{"success":false,"err_str":"No consensus uris specified"}
```

Slam requires talking directly to consensus, not only to mobilecoind.
You can pass these uris as part of the slam request, or, they are optional startup parameters to the faucet.

```
curl -s localhost:9090/slam -d '{"consensus_uris": ["insecure-mc://localhost:3200/", "insecure-mc://localhost:3201/", "insecure-mc://localhost:3202/", "insecure-mc://localhost:3203/"]}' -X POST
```

OR start faucet as

```
$ ./mobilecoind-dev-faucet --keyfile "$LEDGER_BASE/../keys/account_keys_0.json" \
   --peer insecure-mc://localhost:3200/ \
   --peer insecure-mc://localhost:3201/ \
   --peer insecure-mc://localhost:3202/ \
   --peer insecure-mc://localhost:3203/ \
   --peer insecure-mc://localhost:3204/ &
```

and then a slam with no arguments should work.

You can check on the status of a slam by hitting the status endpoint:

```
$ curl -s localhost:9090/status
{"success":true,"b58_address":"5KBMnd8cs5zPsytGgZrjmQ8z9VJYThuh1B39pKzDERTfzm3sVGQxnZPC8JEWP69togpSPRz3e6pBsLzwnMjrXTbDqoRTQ8VF98sQu7LqjL5","faucet_payout_amounts":{"2":"20480","1":"20480","0":"8000000000"},"balances":{"0":"12499999777600000000","1":"0","2":"0"},"queue_depths":{"1":"0","2":"0","0":"0"},"slam_status":"Step 2: Preparing UTXOs: 324/500"}
```

When the slam finishes, the initial post returns a response containing a report like this:

```
{"success":true,"params":{"target_num_tx":500,"num_threads":30,"retries":30,"retry_period":1.0,"tombstone_offset":10,"consensus_client_uris":["insecure-mc://localhost:3200/","insecure-mc://localhost:3201/","insecure-mc://localhost:3202/","insecure-mc://localhost:3203/","insecure-mc://localhost:3204/"]},"report":{"num_prepared_utxos":"500","num_submitted_txs":"500","prepare_time":67.67402,"submit_time":11.472368}}
```

#### Canceling a slam

If slam is taking too long or is stuck, it can be canceled like this:

```
curl -s localhost:9090/cancel_slam -X POST
```
