## MobileCoin CLI client for use with `mobilecoind`

This code demonstrates a text-based client implementation in Python, that uses `mobilecoind` to interact with the MobileCoin network.

### Quick Start

After you [sign up for TestNet](https://forms.gle/ULNjA6cMxCD5XNyT7), we will reach out to you to distribute your TestNet keys. You can start the client with the quickstart scripts below:

1. Start the mobilecoind client to sync the ledger from TestNet

    ```
    ./start-testnet-mobilecoind.sh
    ```

1. Start the interactive client to get and send transactions.

   ```
   ./start-testnet-client.sh
   ```

1. Load your account keys:

    ```
    # load my_accounts.json
    ```

1. Enter `help` or `?` to see a full list of commands, and `help <cmd>` to see help for that command.

### Python client setup

To install required packages for the example client:

(from `mobilecoinofficial/mobilecoin/public/examples/python`)
```
pip3 install -r ./requirements.txt
```

To generate the pb2 files from the protocol buffers:
```
./compile_proto.sh
```

### Running the client

To run the MobileCoin client:
```
python3 ./main.py <host>:<port>
```

This document describes how to start a local `mobilecoind` instance below, for use with the command:
```
python3 ./main.py localhost:4444
```

### Providing an account

You will need to provide your account credentials. During TestNet, your account credentials will be emailed to you, if you sign up [here](https://forms.gle/ULNjA6cMxCD5XNyT7).


### Client interaction

There is a file containing accounts that control funds in the preproduction MobileCoin network provided in `accounts.json`.

An example session:
```
$ ./main.py localhost:4444
# load accounts.json
Loaded 13 accounts.
# monitor alice [0]
Added a monitor for "alice" @ subaddress [0]
# monitor carol [0,1,2]
Added a monitor for "carol" @ subaddress [0,1,2]
# balance alice/0
alice/0 has 5000000000000000 pMOB @ block 12
# transfer 10000 alice/0 carol/1
Transfer initiated.
# status
Transaction not found.
# status
Transaction not found.
# status
Transaction verified.
# balance alice/0
alice/0 has 4999999999990000 pMOB @ block 14
# balance carol/1
carol/1 has 10000 pMOB @ block 15
# balance carol/0
carol/1 has 5000000000000000 pMOB @ block 16
```
