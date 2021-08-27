fog-sample-paykit
=================

The "sample paykit" is a testing object, written in rust, to help validate the
correctness of the server code. It is maintained alongside the servers and used
in integration tests.

"Paykit" means roughly that, it can consume an account key, connect to mobilecoin
and fog servers, perform balance checks and submit transactions.

API
---

To be constructed, the sample paykit requires:
- An `account_key`, with fog support. The sample paykit doesn't support fog-less accounts.
- A mobilecoin consensus URI (to submit transactions)
- A fog view URI (for balance checking)
- A fog ledger URI (for balance checking)

(FIXME: The URI for merkle proofs, and key images, should be separated, and not just one fog ledger URI.)

The primary calls that sample paykit supports (in a blocking, synchronous manner) are

`check_balance`: Returns an `amount` in picomob, and a block count at which that was the balance.
This will reach out to fog view and fog ledger and try to get the most up-to-date balance.
`build_transaction`: Prepare a transaction, using cached balance data. Returns the tx object.
`submit_transaction`: Submit a prepared transaction to the network. Does not guarantee that the network will accept it.
`is_transaction_key_image_present`: Check if a key image from the transaction is now visible in the ledger. This can be used to confirm that the transaction was successful.

Note: The sample paykit `build_transaction` uses cached tx and key image data, but
makes network calls to get merkle proofs and to get fog reports.
An implementation that truly supports offline transactions would not make any network calls
in that function, and would support fetching those data in advance.

scope
-----

The sample paykit is minimalistic and is not expected to ever be used in production.
Its scope is greatly reduced, compared to something like `mobilecoind`:

- It is out of scope to support multiple account keys simultaneously
- It is out of scope to use the same paykit object concurrently
- It is out of scope to serialize the account's transaction data, or any other object state.

The sample paykit primarily is supposed to implement balance checking in a completely correct way,
dealing with distributed systems issues like some servers being ahead and behind.
It also supports building transactions and submitting them to the network, so that we can
do proper integration testing of fog and consensus servers together. (See the `fog-test-client`.)

It should be able to help confirm the correctness of the report server, the correctness around,
what if ingest server crashes and has to be restarted, what if we have "missed blocks", etc.

It is a requirement that it is written entirely in rust, so that it can easily be changed in
the same commit in which these servers change.

So, it does contain a large chunk of the "business logic" of a paykit, and it may be
used as a guide for someone developing a production paykit.

But this should be thought of as test code, and a real production-quality paykit will
not look too much like this. A production paykit would likely support multiple accounts without
requiring increasing numbers of grpc connection objects, and would support
serializing and restoring the account state. It might have optimizations that we didn't do
and configuration options that we didn't provide here.

A production paykit should be able to pass the `fog-conformance-tests`, which this paykit
also should pass at every revision.

libmobilecoin
-------------

It seems likely that we will port this to use `libmobilecoin`, to provide additional
validation of `libmobilecoin`.
