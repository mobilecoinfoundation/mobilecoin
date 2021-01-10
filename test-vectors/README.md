mc-test-vectors
===========

A collection of test vectors for use in conformance testing across platforms.

## Using test vectors when writing tests

The `vectors` directory contains `.jsonl` files, organized by module, where each file represents a test vector that can be made into a test, and each line in the test vector file represents a test case that the test should be run against.

### Writing a test in Rust using a test vector

It is recommended that tests using test vectors be written using the [datatest] crate and take the following form:

```
use mc_util_test_vector::TestVector;

#[datatest::data(<TestVectorImplementationStruct>::from_jsonl("../test-vectors/vectors"))]
#[test]
fn <test_name>(case: <TestVectorImplementationStruct>) {
    <Test code using the values provided by the `case` parameter>
}
```

Note: the `#[test]` line is not strictly necessary, but serves to ensure that IDEs will correctly parse the existence of a test.

[datatest]: https://github.com/commure/datatest

## Adding additional test vectors

Adding additional test vectors involves adding additional structs implementing `TestVector` to the `mc-test-vectors-definitions` crate and adding a corresponding test vector generator crate (or adding to an existing one) whose `build.rs` generates the `.jsonl` test vector files (for an example, see the `mc-test-vectors-account-keys` crate).
 
See the documentation in `util/test-vectors` for more detail on generating test vectors.
