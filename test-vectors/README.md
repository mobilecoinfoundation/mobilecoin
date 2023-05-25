mc-test-vectors
===========

A collection of test vectors for use in conformance testing across platforms.

## Using test vectors when writing tests

The `vectors` directory contains `.jsonl` files, organized by module, where each file represents a test vector that can be made into a test, and each line in the test vector file represents a test case that the test should be run against.

### Writing a test in Rust using a test vector

See [`mc-util-test-vector`](../util/test-vector/README.md) for detailed examples.

## Adding additional test vectors

Adding additional test vectors involves adding additional structs implementing `TestVector` to the `mc-test-vectors-definitions` crate and adding a corresponding test vector generator crate (or adding to an existing one) whose `build.rs` generates the `.jsonl` test vector files (for an example, see the `mc-test-vectors-account-keys` crate).

See [`mc-util-test-vector`](../util/test-vector/README.md) for detailed examples.

## Note on serialization
For some test vectors, values are reported as hex-encoded bytes, which come in
two types: proto and raw.
* Proto bytes are generated from proto serialization methods and in our Rust code that means `mc_util_serial` is used. To deserialize
proto bytes, use your language's corresponding proto deserializatoin methods after
you've decoded the hex.  Fields with the `...hex_proto_bytes` suffix employ
this serialization method.
* Raw bytes are generated using native Rust byte array conversion methods. To
deserialize raw bytes, you'll need to call the corresponding Rust binding method
that calls a native Rust function that performs the conversion. If this binding
doesn't exist, you'll need to create it. Fields with the `...hex_raw_bytes` suffix
employ this serialization method.
