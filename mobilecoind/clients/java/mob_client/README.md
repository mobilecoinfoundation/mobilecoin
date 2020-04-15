# Java sample client and CLI tool

This code serves both as an example of how to use the services provided by mobilecoind
in Java through gRPC and as a CLI tool to interact with mobilecoind.

To use it, you must have an instance of mobilecoind running, this is typically run
locally. You can find instructions at https://github.com/mobilecoinofficial/mobilecoin/tree/master/mobilecoind

A gradle wrapper is included, `gradlew` (or `gradlew.bat` on Windows). The most simple call, assuming you are running
mobilecoind on port 4444 is to create a new root entropy key with the command

```./gradlew run --args='-s localhost:4444 -c generate-entropy'```

This specifies a connection to `localhost` on port `4444` and the commaned `generate-entropy`

If this works, you'll recieve a 256-bit key, encoded as a hex string that might look like this `7ecaf368fa0ce478987b33acd7f9fc9b8b7dacf05a8205668700772e11f98a8d`

To track the transactions in your account, you can add a monitor for this key. A monitor continually scans the ledger for transactions that belong to a key over a large range of subaddresses. The `monitor` command will tell mobilecoind to track a specific key.

```./gradlew run --args='-s localhost:4444 -c monitor -e 7ecaf368fa0ce478987b33acd7f9fc9b8b7dacf05a8205668700772e11f98a8d'```

This will return a monitor key, which is also a 256-bit hex encoded key:
`3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80`

The monitor is now active and will take care of tracking all incoming and spent transactions. You can use this monitor ID to check
the balance for both the key and specific subaddress index:

```./gradlew run --args='-s localhost:4444 -c balance -m 3371207b834e40d9af2c16e762598d7a4e76c4c2d46f90038a374a8bfdff2c80 -i 0'```

Of course since this is a freshly generated account key the balance will be zero. We will be distributing test coins to those
who are interested in helping us with the testnet.