// Copyright (c) 2018-2020 MobileCoin Inc.

//! Export the EDL file location as a variable

use cargo_emit::pair;
use mcbuild_utils::Environment;

fn main() {
    pair!(
        "FILE",
        "{}",
        Environment::default()
            .dir()
            .join("enclave.edl")
            .as_os_str()
            .to_str()
            .expect("Invalid UTF-8 in enclave.edl path")
    );
}
