fog-load-testing
================

This crate contains targets for load-testing various fog servers.

Currently: Ingest
TODO: View, Ledger

This means:

- A standalone binary is invoked to begin testing
- The loadtest binary creates databases in temporary directories, and
  starts the server under test (ingest, view, etc.) with appropriate configuration
  for the test.
- The loadtest binary puts data into databases or submits requests to the server
  over grpc, and watches other databases or grpc responses to wait for a response
  from the server under test.
- The loadtest binary exercises the functionality of interest repeatedly and
  collects timing measurements.
- The loadtest binary does basic statistical analysis of the timing measurements
  and outputs a report.

Example output:

```
root@77969a5da3fc:/tmp/mobilenode/target/release# ./fog_ingest_server_load_test
2020-08-16 08:30:07.815587831 UTC INFO Creating recovery db /tmp/recovery_db.HgV5XmjCve0T, mc.module: fog_lmdb_recovery_db, mc.src: src/fog/lmdb_recovery_db/src/lib.rs:33
2020-08-16 08:30:07.832225092 UTC INFO Opening recovery db /tmp/recovery_db.HgV5XmjCve0T, mc.module: fog_lmdb_recovery_db, mc.src: src/fog/lmdb_recovery_db/src/lib.rs:39
2020-08-16 08:30:07.832368206 UTC INFO Recovery db is currently at version: MetadataVersion { database_format_version: 20200806, created_by_crate_version: "0.3.0", _s: LmdbRecoveryDbMetadataStoreSettings }, mc.module: fog_lmdb_recovery_db, mc.src: src/fog/lmdb_recovery_db/src/lib.rs:194
2020-08-16 08:30:07.863032605 UTC INFO Spawning ingest server: "/tmp/mobilenode/target/release/fog_ingest_server" "--recovery-db=/tmp/recovery_db.HgV5XmjCve0T" "--ledger-db=/tmp/ledger_db.0khQEsULMVlT" "--watcher-db=/tmp/wallet_db.NRnhISypeCZi" "--client-listen-uri=insecure-fog://0.0.0.0:3054/" "--ias-spid" "00000000000000000000000000000000" "--ias-api-key" "00000000000000000000000000000000" "--local-node-id" "127.0.0.1:3054" "--sealed-key" "/root/.test_sealed_key" "--admin-listen-uri=insecure-mca://127.0.0.1:8003/" "--user-capacity" "1048576", mc.module: fog_ingest_server_load_test, mc.src: src/fog/load_testing/src/bin/ingest.rs:198
2020-08-16 08:30:07.863179322 UTC WARN Creating insecure gRPC connection to 127.0.0.1:8003, mc.module: mc_util_grpc::grpcio_extensions, mc.src: public/util/grpc/src/grpcio_extensions.rs:45
2020-08-16 08:30:07.863571772 UTC INFO Waiting for ingest server to become available, mc.module: fog_ingest_server_load_test, mc.src: src/fog/load_testing/src/bin/ingest.rs:214
2020-08-16 08:30:07.869422381 UTC INFO fog_ingest_server started: { "GIT_COMMIT": "57d5c5ea-modified", "PROFILE": "release", "DEBUG": "true", "OPT_LEVEL": "3", "DEBUG_ASSERTIONS": "false", "TARGET_ARCH": "x86_64", "TARGET_OS": "linux", "TARGET_FEATURE": "adx,aes,avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lzcnt,mmx,movbe,pclmulqdq,popcnt,rdrand,rdseed,sse,sse2,sse3,sse4.1,sse4.2,ssse3,xsave,xsavec,xsaveopt,xsaves", "RUSTFLAGS": "?", "SGX_MODE": "SW", "IAS_MODE": "DEV" }, mc.app: fog_ingest_server, mc.module: mc_common::logger::loggers, mc.src: public/common/src/logger/loggers/mod.rs:218
2020-08-16 08:30:07.869562452 UTC INFO State file is "/root/.mc-fog-ingest-state", mc.app: fog_ingest_server, mc.module: fog_ingest_server, mc.src: src/fog/ingest/server/src/bin/main.rs:157
2020-08-16 08:30:12.863807429 UTC INFO Waiting for ingest server to become available, mc.module: fog_ingest_server_load_test, mc.src: src/fog/load_testing/src/bin/ingest.rs:214
2020-08-16 08:30:17.863970445 UTC INFO Waiting for ingest server to become available, mc.module: fog_ingest_server_load_test, mc.src: src/fog/load_testing/src/bin/ingest.rs:214
2020-08-16 08:30:22.864143948 UTC INFO Waiting for ingest server to become available, mc.module: fog_ingest_server_load_test, mc.src: src/fog/load_testing/src/bin/ingest.rs:214
...
Load testing results
================
{ desired_capacity: 1048576 }:
Add 100 users: num samples: 95, avg: 490.28671499999996 ms +/- 37.900709 ms
Process 250 txos: num samples: 95, avg: 1101.146943 ms +/- 89.572068 ms
{ desired_capacity: 8388608 }:
Add 100 users: num samples: 95, avg: 617.234906 ms +/- 46.227719 ms
Process 250 txos: num samples: 95, avg: 1553.961358 ms +/- 132.980845 ms
{ desired_capacity: 16777216 }:
Add 100 users: num samples: 95, avg: 754.7616499999999 ms +/- 59.92367 ms
Process 250 txos: num samples: 95, avg: 1542.809318 ms +/- 104.642014 ms
```
