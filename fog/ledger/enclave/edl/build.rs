// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Export the EDL file location as a variable

use cargo_emit::pair;
use mc_util_build_script::Environment;

fn main() {
    pair!(
        "FILE",
        "{}",
        Environment::default()
            .dir()
            .join("enclave.edl")
            .as_os_str()
            .to_str()
            .expect("Path to EDL file contains invalid UTF-8")
    );
}
