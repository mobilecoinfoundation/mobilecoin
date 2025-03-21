// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Build script, emits source DIR as a variable

use cargo_emit::pair;
use std::{env::var, path::PathBuf};

fn main() {
    let mut search_path =
        PathBuf::from(var("CARGO_MANIFEST_DIR").expect("Could not read CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("Could not canonicalize CARGO_MANIFEST_DIR");
    search_path.push("src");
    let search_path = search_path
        .into_os_string()
        .into_string()
        .expect("Canonicalized CARGO_MANIFEST_DIR contains invalid UTF-8");
    pair!("SEARCH_PATH", "{search_path}", search_path = search_path);
}
