use mc_account_keys_test_vectors_structs::*;
use mc_util_test_vectors::TestVectorWriter;

fn main() {
    // Ensure that the build script isn't rerun when the `.jsonl` test vector files change, as that
    // would cause the build script to be re-run on every compile.
    // See: https://doc.rust-lang.org/cargo/reference/build-scripts.html#change-detection
    println!("cargo:rerun-if-changed=build.rs");

    TestVectorWriter::<DefaultSubaddrKeysFromAcctPrivKeys>::write_jsonl("vectors").unwrap();
    TestVectorWriter::<SubaddrKeysFromAcctPrivKeys>::write_jsonl("vectors").unwrap();
    TestVectorWriter::<AcctPrivKeysFromRootEntropy>::write_jsonl("vectors").unwrap();
}
