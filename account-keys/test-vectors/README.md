mc-account-keys-test-vectors
===========

Crate containing test vectors for use in compliance testing account key implementations across platforms.

## Using test vectors when writing tests

The `vectors` directory contains `.jsonl` files, organized by module, where each file represents a test vector that can be made into a test, and each line in the test vector file represents a test case that the test should be run against.

### Writing a test in Rust using a test vector

It is recommended that tests using test vectors be written using the [datatest] crate and take the following form:

```
use mc_util_test_vectors::TestVectorReader;

#[datatest::data(<TestVectorImplementationStruct>::from_jsonl("test-vectors/vectors"))]
#[test]
fn <test_name>(case: <TestVectorImplementationStruct>) {
    <Test code using the values provided by the `case` parameter>
}
```

Note: the `#[test]` line is not strictly necessary, but serves to ensure that IDEs will correctly parse the existence of a test.

[datatest]: https://github.com/commure/datatest

## Adding additional test vectors

Adding additional test vectors involves adding additional structs to the `mc-account-keys-test-vectors-structs` crate for each additional test vector and implementing the `TestVector` trait for each struct. See the documentation in the `mc-util-test-vectors` crate for more detail on the `TestVector` trait.

Additionally, for each additional struct in `mc-account-keys-test-vectors-structs`, a `write_jsonl` line should be added to the `build.rs` of `mc-account-keys-test-vectors` so that the corresponding test vector file gets generated automatically as part of the build process.
