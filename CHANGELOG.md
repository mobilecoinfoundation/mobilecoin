# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

The crates in this repository do not adhere to [Semantic Versioning](https://semver.org/spec/v2.0.0.html) at this time.

## [Unreleased]

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
