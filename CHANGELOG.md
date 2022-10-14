# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The crates in this repository do not adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) at this time.

## Unreleased

## [2.1.0]

### Added

- Add `Chain-ID` gRPC metadata ([MCIP #49](https://github.com/mobilecoinfoundation/mcips/pull/49)) to provide additional runtime disambiguation between clients and servers.
- Add a required `--chain-id` command-line arguments to consensus and fog servers.
- Add an optional `--chain-id` command-line argument to `mobilecoind`.
- Support using environment variables to set values for nearly all command-line arguments.
- Update CI deployments to use zerossl instead of letsencrypt.
- Add a `--hash-tx-file` subcommand to print the hash of a `mint-tx` or `mint-config-tx` file.
- Add the current block info (fee map, block version, etc.) to the response message for `mobilecoind_api.GetNetworkStatus`.
- Make Jaeger telemetry opt-in using `MC_TELEMETRY=1`. 
- Add a `--block-query-batch-size` parameter to fog-view. This makes fog-view load more data at once from postgres, and helps it to start up faster even if there is high
  network latency in the connection to postgres. This defaults to 1000 now, where previous behavior corresponds to a value of 1.

### Fixes

- Update `mc-consensus-mint-client` to check that public addresses for minting targets do not have a configured fog server.
- Update to `android-bindings` and `libmobilecoin` RNG APIs to assist in idempotent transactions.

### Security

- TOB-MCCT-4: Make minting nonces unique per-token.


## [2.0.0] - 2022-07-25

### Fixed

#### CI/CD

- Fix metadata script for new release branch patterns. ([#2298])

### Security

- Bump SGX to 2.17, mitigate INTEL-SA-00615


## [1.2.2] - 2022-06-17

### Changed

- Updated SGX to 2.16

### Rust Dependencies

- Updated `rust-toolchain` version to newer nightly
  - enables use of [Generic Associated Types](https://github.com/rust-lang/rust/issues/44265) and [static async fn in traits](https://github.com/rust-lang/rust/issues/91611)
- Replaced `datatest` with a custom `test_with_data` macro.
- Replace `structopt` with `clap`.
- Updated `grpcio` from 0.9 to 0.10.

### Changed

- Expose the ability to get a TX shared secret to iOS SDK
- Restore the ability to derive an account from legacy root entropy to iOS SDK
- Improve the construction of `Amount` objects from Android SDK

### Fixed

- Fix panic when consensus service is configured for multiple tokens but still running in MOB-only block-version 0 mode.

## [1.2.0]

### Added

- Encrypted Memos ([MCIP #3](https://github.com/mobilecoinfoundation/mcips/pull/3))
- Recoverable Transaction History ([MCIP #4](https://github.com/mobilecoinfoundation/mcips/pull/4))
- Consensus/Fog repository merge

### Changed

- Updated SGX to 2.15
- Lock enclave no-debug mode when building for IAS production.
- Update Rust toolchain to `nightly-2021-07-21`.

#### Rust Dependencies

- Update `aead` to 0.4.1.
- Update `aes-gcm` to 0.9.2.
- Update `base64` to 0.13.0.
- Update `bindgen` to 0.58.1.
- Update `blake2` to 0.9.2.
- Update `cc` to 1.0.70.
- Update `cfg-if` to 1.0.0.
- Update `cmake` to unreleased github with iOS fixes.
- Update `curve25519-dalek` to 4.0.0-pre1.
- Update `displaydoc` to 0.2.3.
- Update `hashbrown` to 0.11.2.
- Update `hmac` to 0.11.0.
- Update `hostname` to 0.3.1.
- Update `packed_simd_2` to unreleased github with nightly fixes.
- Update `proc-macros2` to 1.0.29.
- Update `quote` to 1.0.9.
- Update `rocket` to 0.4.10.
- Update `semver` to 1.0.4.
- Update `sha2` to 0.9.5.
- Update `subtle` to 2.4.1.
- Update `syn` to 1.0.67.
- Remove `failure` in favor of `displaydoc`.

#### Rust Crate Forks

- Fork `bulletproofs` to `bulletproofs-og` to use dalek upstream, fix clippy issues from upstream.
- Fork `cpufeatures` to disable `CPUID` usage, use fork in enclaves (cargo bug prevents upstreaming).
- Fork `schnorrkel` to `schnorrkel-og`, to use dalek upstream.
- Fork `aes-gcm` to `mc-oblivious-aes-gcm` for oblivious decryption support, use where necessary.

- Update `cmake` fork to fix iOS builds.
- Update `datatest` to support newer rust nightlies.
- Update `ed25519-dalek` fork to support new rust nightlies.
- Update `grpcio` fork to 0.9 base.
- Update `mbedtls`, `mbedtls-sys` forks to support newer rust nightlies.
- Update `x25519-dalek` fork to support newer rust nightlies.

- Unfork `aes-gcm` and update to 0.9.2, use forked `mc-oblivious-aes-gcm` crate in the Fog hint decryption routines.
- Unfork `cpuid-bool`, not used anymore
- Unfork `prost` and update to 0.8.0.

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
