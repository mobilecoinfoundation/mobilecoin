# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The crates in this repository do not adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) at this time.

## [1.2.0] - TBD

### Added

- Fog is now part of this repository
- Fog ledger key image checks are now oblivious ([fog#101])
- Fog View OMAP size configurable via environment
- Fog Overseer utility for monitoring Fog Ingest instances
- Fog Ingest Client CLI now allows queries to the `get_ingress_key_record` API
- Block versioning / protocol evolution ([mcips#26])
- In Block Version 1 (to be enabled along with block version 2):
  - Required Transaction Memos ([mcips#3])
  - Recoverable Transaction History ([mcips#4])
- In Block Version 2 (to be enabled after network has been upgraded):
  - Confidential Multi-Token Support ([mcips#25])
  - Minting support for non-MOB tokens
  - Verifiable burning for any token ([mcips#35])
  - Standardized Addresses for common purposes ([mcips#36])
- In Block Version 3 (will be enabled in a future release):
  - Require TxOuts to be sorted in TxProposal.

### Changed

- Enable `Bitcode` for `libmobilecoin`, reduce mobile artifact size by ~25% ([#1124])
- mobilecoind will now exit on startup when a ledger migration is necessary, unless the new `--ledger-db-migrate` command line argument is used, in which case it will migrate automatically
- Bump SGX versions to 2.16. ([#1101], [#2018])

#### Python

- Bump `ipython` from 7.8.0 to 7.16.3 ([#1333])
- Bump `protobuf` from 3.10.0 to 3.15.0 ([#1477])

#### Rust

- Upgrade rust toolchain to `nightly-2022-04-29` ([#1613], [#1888])
- Replace `datatest` with a custom `test_with_data` attribute macro ([#1556])
- Replace `structopt` with `clap`, and add support for env overrides for all flags ([#1541])

- Fork `bulletproofs` to `bulletproofs-og` to use dalek upstream, fix clippy issues from upstream.
- Fork `cpufeatures` to disable `CPUID` usage, use fork in enclaves (cargo bug prevents upstreaming).
- Fork `opentelemetry` to update some of its dependencies. ([#1918])
- Fork `schnorrkel` to `schnorrkel-og`, to use dalek upstream.
- Unfork `aes-gcm` and update to 0.9.2, use forked `mc-oblivious-aes-gcm` crate in the Fog hint decryption routines.
- Unfork `cpuid-bool`, not used anymore
- Unfork `grpcio` and bump from 0.6 to 0.10.3. ([#1592], [#1717], [#1814])
- Unfork `prost` from bump from 0.8.0 to 0.10.3 ([#898], [#1109], [#1728], [#1809], [#1809], [#1806], [#1805], [#1808], [#1808], [#1807], [#1930], [#1927], [#1926], [#1929])
- Update `cmake` fork to fix iOS builds.
- Update `curve25519-dalek` fork from 4.0.0-pre.0 to 4.0.0-pre.2.
- Update `ed25519-dalek` fork to support new rust nightlies.
- Update `mbedtls`, `mbedtls-sys` forks to support newer rust nightlies, use newer `spin`.
- Update `x25519-dalek` fork to support newer rust nightlies.

- Bump `aead` from 0.3.2 to 0.4.3 ([#1389])
- Bump `aes-gcm` from 0.9.2 to 0.9.4
- Bump `aes` from 0.7.4 to 0.7.5
- Bump `anyhow` from 1.0.39 to 1.0.57 ([#1013], [#1146], [#1265], [#1341], [#1529], [#1578], [#1837])
- Bump `arrayvec` from 0.5.2 to 0.7.1 ([#980])
- Bump `assert_cmd` from 2.0.2 to 2.0.4 ([#1314])
- Bump `backtrace` from 0.3.55 to 0.3.65 ([#982], [#1143], [#1392], [#1817], [#1817])
- Bump `base64` from 0.12.3 to 0.13.0
- Bump `bincode` from 1.3.1 to 1.3.3 ([#1056])
- Bump `bindgen` from 0.51.1 to 0.59.2
- Bump `bitflags` from 1.2.1 to 1.3.2 ([#1016])
- Bump `blake2` from 0.9.1 to 0.10.4 ([#1520])
- Bump `bs58` from 0.3.1 to 0.4.0 ([#948])
- Bump `bs58` from 0.3.1 to 0.4.0
- Bump `cargo-emit` from 0.1.1 to 0.2.1 ([#1045], [#990], [#1000], [#937], [#968])
- Bump `cargo_metadata` from 0.9.1 to 0.14.2 ([#949], [#1135], [#1502])
- Bump `cbindgen` from 0.14.3 to 0.23.0 ([#1020], [#1702], [#1824], [#1824], [#1836])
- Bump `cc` from 1.0.66 to 1.0.73 ([#919], [#920], [#985], [#983], [#1099], [#1094], [#1097], [#1095], [#1096], [#1168], [#1165], [#1166], [#1164], [#1167], [#1501], [#1498], [#1497], [#1499], [#1500])
- Bump `cc` from 1.0.66 to 1.0.70
- Bump `cfg-if` from 0.1.10 to 1.0.0
- Bump `chrono` from 0.4.11 to 0.4.19
- Bump `chrono` to 0.4.19. ([#959])
- Bump `clap` from 3.1.6 to 3.1.18 ([#1762], [#1825], [#1847], [#1904], [#1957])
- Bump `cmake` from 0.1.43 to git-5f89f90ee5d7789832963bffdb2dcb5939e6199c
- Bump `cookie` from 0.14.3 to 0.16.0 ([#1034], [#1271])
- Bump `crc` from 1.8.1 to 2.0.0 ([#1018], [#1138], [#1857])
- Bump `criterion` from 0.3.2 to 0.3.5 ([#1059])
- Bump `crossbeam-channel` from 0.5.0 to 0.5.4 ([#1039], [#1313], [#1678])
- Bump `diesel-derive-enum` from 1.1.1 to 1.1.2 ([#1311])
- Bump `diesel` from 1.4.7 to 1.4.8 ([#1061])
- Bump `digest` from 0.9.0 to 0.10.1.
- Bump `dirs` from 2.0.2 to 4.0.0 ([#1071])
- Bump `displaydoc` from 0.2.0 to 0.2.3 ([#936], [#933], [#995])
- Bump `ed25519` from 1.0.1 to 1.5.0 ([#1179], [#1679], [#1950])
- Bump `futures` from 0.3.8 to 0.3.21 ([#1017], [#1262], [#1458])
- Bump `generic-array` from 0.14.4 to 0.14.5 ([#1315])
- Bump `getrandom` from 0.1.13, 0.2.2 to 0.2.6 ([#986], [#1052], [#1031], [#1310], [#1387], [#1532], [#1531], [#1714], [#1712])
- Bump `ghash` from 0.4.2 to 0.4.4.
- Bump `hashbrown` from 0.6.3 to 0.12.1 ([#899], [#1915])
- Bump `hdkf` from 0.9.0 to 0.12.3
- Bump `hex` from 0.4.2 to 0.4.3 ([#1006], [#923], [#909], [#975], [#913])
- Bump `hmac` from 0.7.1 to 0.12.1.
- Bump `hostname` from 0.1.5 to 0.3.1.
- Bump `itertools` from 0.10.1 to 0.10.3 ([#1200])
- Bump `jni` from 0.16.0 to 0.19.0 ([#1012])
- Bump `libc` from 0.2.97 to 0.2.125 ([#1007], [#1070], [#1112], [#1134], [#1141], [#1159], [#1239], [#1348], [#1365], [#1391], [#1492], [#1525], [#1676], [#1782], [#1826], [#1826], [#1887])
- Bump `libc` from 0.2.98 to 0.2.103.
- Bump `libz-sys` from 1.1.4 to 1.1.6 ([#1591], [#1873])
- Bump `link-cplusplus` from 1.0.5 to 1.0.6 ([#1171])
- Bump `mockall` from 0.8.3 to 0.11.0 ([#956], [#1240])
- Bump `more-asserts` from 0.2.1 to 0.2.2 ([#1174])
- Bump `nix` from 0.18.0 to 0.22.1 ([#1022])
- Bump `num_cpus` from 1.13.0 to 1.13.1 ([#1261])
- Bump `once_cell` from 1.5.2 to 1.9.0 ([#998], [#1249])
- Bump `packed_simd_2` from 0.3.4 to 0.3.7
- Bump `pem` from 0.8.2 to 0.8.3 ([#957], [#1087], [#1131], [#1279])
- Bump `pkg-config` from 0.3.17 to 0.3.25 ([#1033], [#915], [#967], [#925], [#965], [#1072], [#1067], [#1069], [#1066], [#1068], [#1133], [#1127], [#1128], [#1126], [#1125], [#1241], [#1238], [#1235], [#1237], [#1236], [#1755], [#1752], [#1750], [#1753], [#1751])
- Bump `polyval` from 0.5.1 to 0.5.3.
- Bump `predicates` from 1.0.5 to 2.1.1 ([#1142], [#1306])
- Bump `proc-macro2` from 1.0.24 to 1.0.38 ([#1104], [#1130], [#1268], [#1777], [#1938])
- Bump `prometheus` from 0.9.0 to 0.13.0 ([#1002], [#1079])
- Bump `proptest` from 0.10.1 to 1.0.0 ([#952])
- Bump `protobuf` from 2.22.1 to 2.27.1 ([#1754])
- Bump `quote` from 0.6.13 to 1.0.18 ([#1092], [#1355], [#1677], [#1716], [#1795])
- Bump `rand_chacha` from 0.3.0 to 0.3.1 ([#1057])
- Bump `rand_core` from 0.6.2 to 0.6.3 ([#1046], [#930], [#977], [#921], [#947])
- Bump `rand_hc` from 0.3.0 to 0.3.1 ([#1019], [#972], [#916], [#988], [#976])
- Bump `rand` from 0.8.3 to 0.8.5 ([#1041], [#911], [#928], [#914], [#999], [#1489], [#1484], [#1486], [#1485], [#1487])
- Bump `rayon` from 1.3.0 to 1.5.2 ([#992], [#1050], [#1812], [#1812])
- Bump `regex` from 1.3.7 to 1.5.5 ([#1432], [#1590])
- Bump `reqwest` from 0.10.6 to 0.10.10 ([#1054], [#1622])
- Bump `retry` from 1.2.0 to 1.3.0 ([#1036])
- Bump `rocket` from 0.4.6 to 0.5.0-rc2
- Bump `rusoto_s3` from 0.42 to 0.48. ([#1912])
- Bump `secrecy` from 0.4.1 to 0.8.0 ([#950], [#1043])
- Bump `semver` from 0.11.0 to 1.0.9 ([#1459], [#1528], [#1715], [#1900])
- Bump `sentry` from 0.24.3 to 0.25.0 ([#1563])
- Bump `serde_json` from 1.0.60 to 1.0.81 ([#1023], [#1155], [#1170], [#1278], [#1322], [#1344], [#1488], [#1916])
- Bump `serde` from 1.0.118 to 1.0.137 ([#996], [#991], [#939], [#940], [#941], [#1277], [#1273], [#1276], [#1274], [#1275], [#1351], [#1383], [#1363], [#1350], [#1386], [#1903], [#1897], [#1901], [#1894], [#1895])
- Bump `serde` from 1.0.118 to 1.0.130.
- Bump `serial_test_derive` from 0.5.0 to 0.5.1 ([#1001])
- Bump `serial_test` from 0.5.0 to 0.5.1 ([#1044])
- Bump `sha2` from 0.8.1 to 0.10.2 ([#1512], [#1509])
- Bump `sha3` from 0.9.1 to 0.10.0.
- Bump `signal-hook` from 0.3.4 to 0.3.13 ([#1008], [#1263])
- Bump `signature` from 0.2.2 to 1.4.0 ([#1115])
- Bump `siphasher` from 0.3.1 to 0.3.10 ([#942], [#1003], [#1321], [#1579])
- Bump `slog-async` from 2.5.0 to 2.7.0 ([#1060])
- Bump `slog-atomic` from 3.0.0 to 3.1.0 ([#1010])
- Bump `slog-json` from 2.3.0 to 2.6.1 ([#978], [#1343], [#1757])
- Bump `slog-json` from 2.3.0 to 2.4.0.
- Bump `slog-scope` from 4.3.0 to 4.4.0 ([#1049])
- Bump `slog-stdlog` from 4.1.0 to 4.1.1 ([#1692])
- Bump `slog-term` from 2.6.0 to 2.8.0 ([#1042], [#1524])
- Bump `subtle` from 1.0.0 to 2.4.1.
- Bump `syn` from 0.15.44 to 1.0.94 ([#979], [#1064], [#1090], [#1098], [#1132], [#1291], [#1332], [#1642], [#1713], [#1776], [#1886], [#1956], [#1976])
- Bump `tempfile` from 3.2.0 to 3.3.0 ([#1758])
- Bump `tiny-bip39` from 0.8.0 to 0.8.2 ([#1053], [#1080])
- Bump `toml` from 0.5.7 to 0.5.9 ([#1011], [#1815])
- Bump `url` from 2.1.1 to 2.2.2 ([#951])
- Bump `walkdir` from 2.3.1 to 2.3.2 ([#997], [#962], [#931], [#974], [#922])
- Bump `yaml-rust` from 0.4.4 to 0.4.5 ([#993])
- Bump `zeroize` from 1.2.0 to 1.5.5 ([#908], [#1028], [#1027], [#1029], [#1156], [#1366], [#1360], [#1656], [#1902], [#1898], [#1899], [#1896])

### Removed

- The `slam` test utility, in favor of `fog-distribution` ([#1611])
- Support for root entropy-based key derivation in test keys/ledgers ([#1893])
- The `pretty_assertions` dependency ([#1055], [#1078], [#1431], [#1610], [#1657])

### Fixed

- Fog ingest state file handling is more resilient ([#1358])
- Fog services sometimes returned the wrong grpc error code for attestation failures
- Added retries for connectivity issues with Postgres database in Fog services

### Security

- Fixed a problem with data authentication in the Fog OCALL Oram Storage interface (Thanks to [@AmbitionXiang] for reporting!, [#1576])


## [1.1.1] - 2021-08-16

### Changed

 - Updated TOS.
 - Update IP restriction handling in mobilecoind to match TOS.

## [1.1.0] - 2021-06-08

### Added

 - Mnemonics-based Key Derivation
 - Dynamic Fees [rfcs/#1](https://github.com/mobilecoinfoundation/rfcs/#1)
   - `consensus-service` now takes `--minimum-fee=<picoMOB>` to configure minimum fees (nodes with different fees cannot attest to each other).
   - `mobilecoind`'s `GenerateOptimizationTxRequest` API to takes a user-supplied fee.
 - Authenticated fog details in public addresses
 - Admin gRPC for `mobilecoind`.
 - `mc-slam` load generation utility.
 - `mc-sgx-css-dump` SIGSTRUCT (CSS) debug utility.
 - `mobilecoind` can send change to a designated subaddress.
 - `mobilecoind` support for load balancing (via forked grpcio).
 - `mobilecoind` encrypts account key at rest.
 - `watcher` app to keep track of Attestation Verification Reports from live machines.

### Changed

 - Bump ISV SVN for consensus enclave to 2
 - Reduce minimum fee from 10mMOB to 400uMOB
 - Parallelize HTTP transaction fetcher
 - Optionally seed RNGs for mock attestation signer from `MC_SEED` env.
 - Bump rust version to `nightly-2021-03-25`
 - Update SGX to 2.13.3.
 - Use `AWS_REGION` instead of `?region=`.
 - Make enclave errors (to clients/peers) result in `PERMISSION_DENIED` to force reattestation.
 - Fog hints now use AES256-GCM

#### Rust Dependencies

 - Update `anyhow` to 1.0.39
 - Update `arc-swap` to 0.4.8
 - Update `arrayvec` to 0.5.2
 - Update `backtrace` to 0.3.55
 - Update `base64` to 0.12.3
 - Update `bigint` to 4.4.3
 - Update `blake2` to 0.9.1
 - Update `cc` to 1.0.66
 - Update `cfg-if` to 1.0.0
 - Update `cookie` to 0.14.3
 - Update `crossbeam-channel` to 0.5.0
 - Update `curve25519-dalek` to 4.0.0-pre.0
 - Update `datatest` to 0.6.4
 - Update `displaydoc` to 0.2.0
 - Update `fs_extra` to 1.2.0
 - Update `futures` to 0.3.8
 - Update `hmac` to 0.10.1
 - Update `indicatif` to 0.15.0
 - Update `libc` to 1.0.80
 - Update `mockall` to 0.8.3
 - Update `once_cell` to 1.5.2
 - Update `pem` to 0.8.2
 - Update `proc-macro2` to 1.0.24
 - Update `proptest` to 0.10.1
 - Update `protobuf` to 2.22.1
 - Update `rand_core` to 0.6.2
 - Update `rand_hc` to 0.3.0
 - Update `rand` to 0.8.3
 - Update `reqwest` to 0.10.6
 - Update `retry` to 1.2.0
 - Update `rocket` to 0.4.6
 - Update `semver` to 0.11.0
 - Update `serde_json` to 1.0.60
 - Update `serde` to 1.0.118
 - Update `serial_test` to 0.5.0
 - Update `sha2` to 0.9.3
 - Update `slog-stdlog` to 4.1.0
 - Update `slog-term` to 2.6.0
 - Update `structopt` to 0.3.21
 - Update `syn` to 1.0.45
 - Update `tempfile` to 3.2.0
 - Update `thiserr` to 1.0.24
 - Update `toml` to 0.5.7
 - Update `unicode-normalization` to 1.1.17
 - Update `version_check` to 0.9.3
 - Update `x25519-dalek` to 1.1.0
 - Update `zeroize` to 1.2.0

#### Upstream Forks

 - Unfork `bulletproofs` to unreleased 2.0.0 from github
 - Fork `grpcio` to a 0.6.0 fork that supports cookies
 - Fork `aes-gcm` 0.6.0 to support constant-time decrypt results

#### Python Dependencies

 - Update `jinja` to 2.11.3
 - Update `pygments` to 2.7.4

### Fixed

 - Remove unnecessary limits on consensus request concurrency
 - Readme fixes (thanks to contributors @hiqua, @petertodd)
 - Fix monitor ID instability in `mobilecoind`.
 - Normalize fog URL in public addresses before lookup
 - Unified rustfmt

### Security

 - Make encryption/decryption success able to be used from within a larger constant-time context for `mc-crypto-box`.
 - Stricter EPID Pseudonym length test. (IoActive MC-03)

## [1.0.0] - 2020-11-24

Initial release.
