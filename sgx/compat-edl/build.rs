// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Build script, emits source DIR as a variable

use cargo_emit::pair;
use std::{convert::TryFrom, env::var, path::PathBuf};

fn main() {
    for (key, value) in std::env::vars() {
        eprintln!("env:{}={}", &key, &value);
    }

    let mut compat_search_path =
        PathBuf::try_from(var("CARGO_MANIFEST_DIR").expect("Could not read CARGO_MANIFEST_DIR"))
            .expect("Could not construct PathBuf from CARGO_MANIFEST_DIR")
            .canonicalize()
            .expect("Could not canonicalize CARGO_MANIFEST_DIR");
    compat_search_path.push("src");
    let compat_search_path = compat_search_path
        .into_os_string()
        .into_string()
        .expect("Canonicalized CARGO_MANIFEST_DIR contains invalid UTF-8");

    let mut debug_search_path = PathBuf::try_from(
        var("DEP_SGX_DEBUG_EDL_SEARCH_PATH").expect("Could not read DEP_SGX_DEBUG_EDL_SEARCH_PATH"),
    )
    .expect("Could not construct PathBuf from DEP_SGX_DEBUG_EDL_SEARCH_PATH")
    .canonicalize()
    .expect("Could not canonicalize DEP_SGX_DEBUG_EDL_SEARCH_PATH");
    debug_search_path.push("src");
    let debug_search_path = debug_search_path
        .into_os_string()
        .into_string()
        .expect("Canonicalized DEP_SGX_DEBUG_EDL_SEARCH_PATH contains invalid UTF-8");

    let mut panic_search_path = PathBuf::try_from(
        var("DEP_SGX_PANIC_EDL_SEARCH_PATH").expect("Could not read DEP_SGX_PANIC_EDL_SEARCH_PATH"),
    )
    .expect("Could not construct PathBuf from DEP_SGX_PANIC_EDL_SEARCH_PATH")
    .canonicalize()
    .expect("Could not canonicalize DEP_SGX_PANIC_EDL_SEARCH_PATH");
    panic_search_path.push("src");
    let panic_search_path = panic_search_path
        .into_os_string()
        .into_string()
        .expect("Canonicalized DEP_SGX_PANIC_EDL_SEARCH_PATH contains invalid UTF-8");

    pair!(
        "SEARCH_PATH",
        "{compat}:{debug}:{panic}",
        compat = compat_search_path,
        debug = debug_search_path,
        panic = panic_search_path
    );
}
