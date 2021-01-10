# Java sample client and CLI tool

This code serves both as an example of how to use the services provided by mobilecoind
in Java through gRPC and as a CLI tool to interact with mobilecoind.

To use it, you must have an instance of mobilecoind running, this is typically run
locally. You can find instructions at https://github.com/mobilecoinfoundation/mobilecoin/tree/master/mobilecoind

A gradle wrapper is included, `gradlew` (or `gradlew.bat` on Windows). The most simple call, assuming you are running
mobilecoind on port 4444 is to create a new root entropy key with the command

```./gradlew run --args='-s localhost:4444 -c generate-entropy'```

This specifies a connection to `localhost` on port `4444` and the commaned `generate-entropy`

If this works, you'll recieve a 256-bit key, encoded as a hex string that might look like this `7ecaf368fa0ce478987b33acd7f9fc9b8b7dacf05a8205668700772e11f98a8d`

Rather than run all the commands using `gradlew`, you can build a distribution using `./gradlew distZip` which will build a usable binary. You can also get the distribution `mob_client.zip` from the releases page.

To track the transactions in your account, you can add a monitor for this key. A monitor continually scans the ledger for transactions that belong to a key over a large range of subaddresses. The `monitor` command will tell mobilecoind to track a specific key.

```./mob_client -s localhost:4444 -c monitor -e 7ecaf368fa0ce478987b33acd7f9fc9b8b7dacf05a8205668700772e11f98a8d```

This will return a monitor key, which is also a 256-bit hex encoded key:

`3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80`

The monitor is now active and will take care of tracking all incoming and spent transactions. You can use this monitor ID to check
the balance for both the key and specific subaddress index:

```./mob_client -s localhost:4444 -c balance -m 3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80 -i 0```

Of course since this is a freshly generated account key the balance will be zero. We will be distributing test coins to those
who are interested in helping us with the testnet.

To recieve a payment you'll need to generate a request code (or public address) using the `request` command which you
can then share with with someone else.
```./mob_client -s localhost:4444 -c request -m 3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80 -i 1```

Every key and subaddress index has a unique code. These are represented as b58 encoded strings and include a checksum so
they will not accidentally be mistyped, e.g.:

```3WkD1Caa5XtfogSX1k7tRpq7BUCLSgZdfhjXcZHYV9oj68G3ebjkRwqe8HvSeCobD2iEnAib8VssosjwXDE6btSGMXZ3pQnmKGWGqwSaJvLwWo```

You can use this request code to transfer between your own subaddress indices, or you can give it to someone else and
have them send you a payment using the `transfer` command:

```./mob_client -s localhost:4444 -c transfer -m 3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80 -i 0 -r 3WkD1Caa5XtfogSX1k7tRpq7BUCLSgZdfhjXcZHYV9oj68G3ebjkRwqe8HvSeCobD2iEnAib8VssosjwXDE6btSGMXZ3pQnmKGWGqwSaJvLwWo -a 50000```

This will print a `reciept` which you can use to check the status of your transfer using the `status` command:

```./mob_client -s localhost:4444 -c status -r 1ad7dfb8a36a637d717aa7b272e49ce05d267ad1927898b7f2b5b9a40306a443:116```
