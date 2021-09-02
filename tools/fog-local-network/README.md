fog-local-testing
=================

This directory contains python utilities for testing fog:

- `fog_local_network.py` starts a consensus network with attached fog services, for local experimentation.
  For example you can run the test client manually against this network, entirely locally and without deploying it.
- `fog_conformance_test.py` mocks the consensus network and attaches fog services to the ledger.
  This conformance test tests that a balance-checking procedure is working correctly and tolerates
  conditions like fog-view being ahead of fog-ledger and vice versa.

fog_local_network
-----------------

The `fog_local_network.py` script is meant to assist in running a fog-enabled local network. It relies on `mobilecoin/tools/local-network/local_network.py` for starting a consensus network, and then add the various fog services on top of it.

In order to use it, the following steps are necessary.
1) Create and `cd` into a work directory in which keys and ledger would be created.
    ```
    mkdir fog-test
    cd fog-test
    ```

2) Generating a set of sample keys:
    ```
    cargo run -p mc-util-keyfile --bin sample-keys --release --manifest-path ../Cargo.toml -- --num 1000 --fog-report-url 'insecure-fog://localhost:6200'
    ```

    Some important things to note:
    - This would create a `keys` directory in the current directory where the keys would be placed.
    - The account server name is not actually used by bootstrap to generate meaningful hints, but is still useful to have so that the key files have it.
    - The URL points at the fog report server that would be started by the Python script. In the current design, the fog URL inside a public address has to point at the report server, and the report server needs to have a report for an ingest server with a matching URL. As such, the ingest server is started with `--fqdn=insecure-fog://localhost:6200`.

3) Bootstrap a ledger:
    ```
    cargo run --manifest-path ../util/generate-sample-ledger/Cargo.toml --release -- --txs 100
    ```

4) Start a local network, for example:
    ```
    SGX_MODE=SW IAS_MODE=DEV \
    MC_LOG="trace,rustls=warn,hyper=warn,tokio_reactor=warn,mio=warn,want=warn,rusoto_core=error,h2=error,reqwest=error,rocket=error,<unknown>=error" \
    GRAFANA_PASSWORD="... (get this from a team member, optional) \"
    LOGSTASH_HOST="... (get this from a team member, optional)" \
    LOG_BRANCH=eran-local \
    LEDGER_BASE=$(pwd)/ledger \
    IAS_SPID="..." \
    IAS_API_KEY="..." \
    python3 ../tools/fog-local-network/fog_local_network.py --network-type dense5
    ```
    Note that all of the above arguments are identical to the mobilecoin local_network.py script.
    The script is known to work with python 3.6 or later

4) Wait for the network to start. This takes awhile. You can tell by looking at the log messages and noticing when they slow down/end. At this point you have a local network running with fog. If you want to test it, see the following steps.

5) Distribute coins with usable fog hints:
    ```
    # Create a set of target keys. They would be identical to the first N keys inside `keys/`. This is needed if you don't
    # want to send to transactions to all 1000 keys created at step 1.
    # Notice the addition of the --output-dir argument
    cargo run -p mc-util-keyfile --bin sample-keys --release --manifest-path ../Cargo.toml -- --num 10 --output-dir fog_keys --fog-report-url 'insecure-fog://localhost:6200' --fog-authority-root $(../target/release/mc-crypto-x509-test-vectors --type=chain --test-name=ok_rsa_head)

    # Run the distribution script. This takes awhile and you should see transactions going through by looking at the logs.
    SGX_MODE=SW IAS_MODE=DEV MC_LOG=debug \
    INGEST_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    LEDGER_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    VIEW_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    CONSENSUS_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
        cargo run -p mc-fog-distribution --release -- \
        --sample-data-dir . \
        --peer insecure-mc://localhost:3200/ \
        --peer insecure-mc://localhost:3201/ \
        --peer insecure-mc://localhost:3202/ \
        --peer insecure-mc://localhost:3203/ \
        --peer insecure-mc://localhost:3204/ \
        --num-tx-to-send 1
    ```

    Note that `fog-distribution` does not wait for the transactions it submitted to complete.

6) When its done, wait for consensus to complete processing the transactions (by looking at the logs). Afterwards you should be able to successfully run the test client:
    ```
    SGX_MODE=SW IAS_MODE=DEV MC_LOG=trace \
    INGEST_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    LEDGER_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    VIEW_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
    CONSENSUS_ENCLAVE_PRIVKEY=$(pwd)/../Enclave_private.pem \
        cargo run -p mc-fog-test-client -- \
        --consensus insecure-mc://localhost:3200/ \
        --consensus insecure-mc://localhost:3201/ \
        --consensus insecure-mc://localhost:3202/ \
        --consensus insecure-mc://localhost:3203/ \
        --consensus insecure-mc://localhost:3204/ \
        --num-clients 6 \
        --num-transactions 32 \
        --consensus-wait 300 \
        --transfer-amount 20 \
        --fog-view insecure-fog-view://localhost:8200 \
        --fog-ledger insecure-fog-ledger://localhost:8200 \
        --key-dir $(pwd)/fog_keys
    ```

fog_conformance_test
--------------------

The fog conformance tests are an integration-style test that attempts to validate
an implementation of mobilecoin balance check protocol is working as expected,
even in the face of adverse network conditions.

These tests deploy all fog services locally, create keys and bootstrap a ledger.
Consensus is mocked out for this test. The ledger is evolved deterministically,
and two copies of the ledger exist, one which is input to ingest and one to view,
in order to control which one is ahead or behind.

Usage
-----

1. Set `IAS_API_KEY` and `IAS_SPID` if needed, otherwise they will default to all zeros. In a DEV IAS build that is fine.
1. Create a new Python3 virtual env: `python3 -mvenv env`
1. Activate the virtualenv: `. ./env/bin/activate`
1. Install requirements: `pip install --upgrade pip && pip install -r requirements.txt`
1. Compile the protobuf files into a python module: `./build.sh`
1. Start the fog conformance test script: `./tools/fog-local-network/fog_conformance_test.py`

You can build the servers and test in release mode instead:
`./tools/fog-local-network/fog_conformance_test.py --release`

If you have already built in mobilecoin and fog, you can skip the build step with `--skip-build`.

Overview
--------

The `fog-conformance-tests` works as follows:
- Databases corresponding to the "inputs" to fog, that is, the ledger db and watcher db,
  are written out and controlled deterministically by the conformance test. There is
  no consensus server or mobilecoind involved, we are essentially mocking those out.
- A fog pipeline is stood up, invoking the actual release-mode binaries, and standing
  up all servers relevant to balance checking.
- The `sample_paykit_remote_wallet` binary starts a GRPC server that wraps the sample paykit, providing
  an a GRPC API the fog conformance test can use to exercise the sample paykit.
- The conformance test drives the inputs to the servers in a fixed way, ensuring
  that at different steps, view is ahead of ledger, ledger is ahead of view etc.,
  and a correct balance is computed despite this.

Examples of bugs that should be caught by this:
- Bob has 100 MOB and spends 1 MOB to buy a sandwich. The transaction lands in block 11.
  A correct balance is 100 MOB at any time before block 11, and 99 MOB after block 11.
  If view is ahead of ledger and the client doesn't handle that well, they could display
  199 MOB, because they see the original transaction and the change transaction, but not
  the key image for the original transaction.
  If ledger is ahead of view and the client doesn't handle that well, they could display
  0 MOB, because they see the original transaction's key image and not the change tx out.
- Ingest server crashes and there are missed blocks, but Bob's client doesn't get the memo.
  Bob's client sees some of his transactions being burned and not his new outputs, and
  displays a 0 balance.

Test coverage goals:
- The conformance test should test that generally if some servers are ahead of others,
  this does not cause a balance to be wrong.
- The conformance test should test that if the balance check process is restarted and it
  recomputes balances from scratch, it still computes the correct balance, in many such
  scenarios.
- The conformance test should also exercise ingest key rotation etc. pathways.
  to validate that balances are still correct thereafter (not done yet).
- The conformance test should also exercise the missed block scenario (not done yet).

Non-goals:
- The conformance test should not attempt to confirm that the SDK can submit transactions.
  It should be out of scope to run consensus or mobilecoind.

Interface
---------

We have experimented with several different strategies for integration testing in mobilecoin now.
- Rust server objects inside cargo unit tests (this was the e2e test crate)
  This has some drawbacks: (1) we aren't actually testing the binaries we ship
  (2) some hacks are required to work around per-process limitations of lmdb
  (3) we weren't exercising the actual command-line APIs of the servers
- Rust process which uses `std::process::Command` to launch a server and test it
  (this is the `fog-load-testing` approach)
  This has some drawbacks: need to roll our own sigchld handler, might not work well
  if there's more than one process. Requires some annoying low-level work like this.
- Python process which starts all the servers with subprocess module. (This is the `fog-local-network` approach)
  This has the advantage that python is pretty easy to use and mature for scripting needs like this,
  and we already have something that uses this approach and works well, and we can share a lot of code with it.

So, all things considered, a python script seems like the way to go.
However, there are not direct python bindngs to the inputs (the databases) or the outputs (the remote wallet).

Additionally, the remote wallet interface needs to be language-agnostic, so that the rust `fog-sample-paykit` can be easily
swapped out for Swift or Java SDK implementations in the test.

In order to provide a way to easily replace the wallet implementation with a different one, the fog conformance test script interacts with a general-purpose wallet interface (see fog/sample-paykit/proto/remote_wallet.proto) over GRPC. An example implementation, `sample_paykit_remote_wallet` is provided.

This is intended to be as easy as possible to conform to for an SDK in rust, swift, or java, without making python bindings.

Additionally, we create CLI tools written in rust to append test blocks to the `ledger_db` and `watcher_db`, so that
python can easily drive the scenario tests.

Note: To work with the conformance test, a client must implement balance checking in a way that it produces both a balance and a time
that that balance was correct, measured by block count. So, balance checking yields an assertion "my balance was this, after this block",
rather than simply a number.
Fog does give the client enough information to do this, so it should be able to do this for purpose of the test.
The client likely needs to track this sort of information anyways in order to be resilient against the types of race conditions being tested here.
