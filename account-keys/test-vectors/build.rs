use mc_account_keys_test_vectors_structs::*;
use mc_util_test_vectors::TestVectorWriter;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    TestVectorWriter::<DefaultSubaddrKeysFromAcctPrivKeys>::write_jsonl("vectors").unwrap();
    TestVectorWriter::<SubaddrKeysFromAcctPrivKeys>::write_jsonl("vectors").unwrap();
    TestVectorWriter::<AcctPrivKeysFromRootEntropy>::write_jsonl("vectors").unwrap();
}
