Cargo build-script utilities for automatic compilation of protobuf files.

This crate provides a programatic API for dealing with protobuf files compilation into Rust code that can be used by GRPC clients and servers.
It relies on `protoc_grpcio` to do the actual compilation. The extra functionality provided by it is storing the auto-generated code outside of `src/`. Instead, the code is stored in `OUT_DIR` (`target/`). That functionality does not exist in `protoc_grpcio` and requires the boilterplate code provided by this crate.
