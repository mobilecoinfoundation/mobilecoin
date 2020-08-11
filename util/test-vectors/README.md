mc-util-test-vectors
===========

Code to help facilitate generating and using test vectors.

## Usage

### TestVector

The `TestVector` trait should be implemented by a struct representing a test case. The struct should have whatever fields are required to carry out the test, and should be serializable/deserializable using `serde`.

The `generate()` function should return a `Vec` of test cases that will be used as test vectors during testing.

<details><summary>Example</summary>

```Rust
#[derive(Debug, Serialize, Deserialize)]
pub struct AcctPrivKeysFromRootEntropy {
    pub root_entropy: [u8; 32],
    pub view_private_key: RistrettoPrivate,
    pub spend_private_key: RistrettoPrivate,
}

impl TestVector for AcctPrivKeysFromRootEntropy {
    const FILE_NAME: &'static str = "acct_priv_keys_from_root_entropy";
    const MODULE_SUBDIR: &'static str = "identity";

    fn generate() -> Vec<Self> {
        (0..10)
            .map(|n| {
                let root_entropy = [n; 32];
                let account_key = AccountKey::from(&RootIdentity::from(&root_entropy));
                Self {
                    root_entropy,
                    view_private_key: *account_key.view_private_key(),
                    spend_private_key: *account_key.spend_private_key(),
                }
            })
            .collect::<Vec<_>>()
    }
}
```

In this example, a single instance of `AcctPrivKeysFromRootEntropy` represents a single test case. For this test, the `root_entropy` field will be used as input to create an `AccountKey` and `AcctPrivKeysFromRootEntropy`'s `view_private_key` and `spend_private_key` fields will be the expected values for the test case, which in this particular test will be compared against the corresponding fields of `AccountKey`.

For this test vector, a list of 10 test cases are generated, with the index being used as the repeating value in the `root_entropy` array.

</details>

### TestVectorWriter

`TestVectorWriter` should be used to write the serialized `TestVector` to a `.jsonl` file. The file will be outputted in [json lines] format, where each line is single test case in the form of a json dictionary, serialized from the struct implementing `TestVector`.

The recommended place to use `TestVectorWriter` is in the `build.rs` of a crate dedicated to this purpose. This allows the generation of the test vectors to be executed as part of the Cargo build process.

In practice this means that there will be a crate containing the `TestVector` implementation structs, and another one containing the `build.rs` script for generating the test vector files. The reason for 2 crates instead of 1 is that the `build.rs` cannot reference code in its own `lib.rs`, therefore the `TestVector` implementation structs must exist in a separate crate, which will then be a build dependency of the crate with the `build.rs`.

In order to ensure that the test vector files are regenerated during a build, the crate with the `build.rs` should be a `dev-dependency` of another crate, such that the crate with the `build.rs` is in the dependency tree of whatever is being built.

This is not strictly necessary, however, since the crate that generates the test vector files can be specified directly when invoking Cargo, or if workspaces are used, can be added to the workspace and therefore will be included implicitly when building the workspace as a whole.

When used with a `build.rs`, the `.jsonl` test vectors files will be written to the directory specified by the `write_jsonl` function's `dir` parameter relative to the crate containing the `build.rs`. The test vector files will be organized into subdirectories based on the module specified by each `TestVector` implementation.

[json lines]: http://jsonlines.org/

<details><summary>Example</summary>

```Rust
// build.rs

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    TestVectorWriter::<AcctPrivKeysFromRootEntropy>::write_jsonl("vectors").unwrap();
}
```

In this example, the test vector files will be located in the `vectors` folder within the crate containing this `build.rs`.

The `println!("cargo:rerun-if-changed=build.rs");` line ensures that the `build.rs` isn't re-run every time the test vector files change, since that would cause the build script to be re-run on every compile. (see https://doc.rust-lang.org/cargo/reference/build-scripts.html#change-detection)

</details>

### TestVectorReader

`TestVectorReader` should be used in conjunction with the [datatest] crate. The `from_jsonl` function should be used with `datatest::data` when composing tests in order to read the corresponding `.jsonl` test vector file containing the test cases.

The test function should have only 1 parameter. That parameter should be a type that is deserializable from the individual lines in the corresponding `.jsonl` test vector file.

The `.jsonl` file that's loaded is the file pointed to by the `TestVector` implementation used in the `#[data()]` directive. This does not necessarily have to be the same type as the parameter to the test function, but it is more convenient if it is.

[datatest]: https://github.com/commure/datatest

<details><summary>Example</summary>

```Rust
#[data(AcctPrivKeysFromRootEntropy::from_jsonl("test-vectors/vectors"))]
#[test]
fn acct_priv_keys_from_root_entropy(case: AcctPrivKeysFromRootEntropy) {
    let account_key = AccountKey::from(&RootIdentity::from(&case.root_entropy));
    assert_eq!(
        account_key.view_private_key().to_bytes(),
        case.view_private_key.to_bytes()
    );
    assert_eq!(
        account_key.spend_private_key().to_bytes(),
        case.spend_private_key.to_bytes()
    );
}
```

In this example, `"test-vectors/vectors"` is the location of the test vectors folder relative to the crate containing the test.

This test will be run 10 times, once for each line in the corresponding `.jsonl` test vector file.

Note: the `#[test]` line is not strictly necessary, but serves to ensure that IDEs will correctly parse the existence of a test.

</details>
