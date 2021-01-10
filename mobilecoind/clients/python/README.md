## Python and `mobilecoind`

### Starting `mobilecoind`

These examples assume that `mobilecoind` is available without SSL, on `localhost` port `4444`. You can start up an instance of `mobilecoind` by running the included shell script `start-mobilecoind.sh`

Usage:
```

./start-mobilecoind.sh [options: --clean]

```

If you include the option `--clean` any previously downloaded release packages and database files will be replaced.

### Examples


#### CLI tools

This directory contains simple command line utilities for interacting with the MobileCoin network using python and `mobilecoind`:
 * `check_balance.py`
 * `send_payment.py`
 * `get_public_address.py`
 * `benchmark.py`
 * `cleanup_monitors.py`

See the included README.md file for details.

#### Blockchain Explorer

The `blockchain_explorer` directory contains a simple webserver that displays the raw blockchain content that `mobilecoind` downloads.

See the [blockchain_explorer README](./blockchain_explorer/README.md) for more info.

#### Jupyter Wallet

This simple example demonstrates using Python with `mobilecoind` to send a transaction.

Install and use [jupyter](https://jupyter.org/) to view the example [wallet notebook](./jupyter/wallet.ipynb).


#### PizzaMOB Leaderboard

This directory contains a webserver that was used in a TestNet game during the summer of 2020.

Usage:
```

python3 ./pizzamob_leaderboard.py --entropy <master key as a 64 character hexidecimal string>

```

You can then view the leaderboard website at http://localhost:5000


## The `mobilecoin` Python Library

The `lib` directory contains the source for the `mobilecoin` library available at [PyPi](https://pypi.org/project/mobilecoin).
