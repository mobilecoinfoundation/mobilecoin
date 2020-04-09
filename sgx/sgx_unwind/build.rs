// Copyright (c) 2018-2020 MobileCoin Inc.

// See rust src/libunwind/build.rs, we have taken only the parts relevant to sgx

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rustc-link-lib=gcc_s");
}
