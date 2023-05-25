fog_test_infra
==============

Infrastructure for various kinds of integration and conformance tests.

This includes mocks of various objects, and generic conformance tests written against
various interfaces (traits).

- `db_tests` contains generic conformance tests against implementations of
  `fog_recovery_db_iface` traits.
- `mock_db` contains a mock recovery db built using Mutexes and HashMaps, for
  comparison with an actual database like lmdb.
- `mock_users` contains infrastructure around the `tx_recovery` tests in ingest server.
  This is a mock pool of users which generates a stream of transactions between them,
  and tests that the output of the ingest server (into some database implementation)
  is enough to support transaction recovery.
- `mock_client` is a "pass-through" implementation of the trait implemented by the view grpc client.
  The pass-through reads directly from the recovery database, non-obliviously.
  This is used in the `tx_recovery` tests and can also be used to test the conformance of the
  actual view server.
