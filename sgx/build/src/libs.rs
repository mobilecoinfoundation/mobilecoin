// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::conf::*;
use std::env;

use lazy_static::lazy_static;

// A static to ensure that we lazily emit rustc-link-search=native directive,
// and only once
lazy_static! {
    static ref MAYBE_EMIT_LIB_DIR: bool = {
        println!(
            "cargo:rustc-link-search=native={}",
            (*SDK_LIB_DIR).display()
        );
        true
    };
}

// Helper functions
fn link(libtype: &str, libname: &str, postfix: &str) {
    println!("cargo:rustc-link-lib={}={}{}", libtype, libname, postfix);
    println!(
        "cargo:warning=Linking rust {} against {}{}",
        env::var("CARGO_PKG_NAME").expect("Could not get package name from environment"),
        libname,
        postfix
    );
}

pub fn sim_postfix() -> &'static str {
    if *SGX_MODE_SIM {
        "_sim"
    } else {
        ""
    }
}

// SDK libraries

// Used in untrusted code
pub fn link_sgx_capable() {
    let _ = *MAYBE_EMIT_LIB_DIR;
    link("static", "sgx_capable", "");
}

// Used in untrusted code, counterpart is tservice
pub fn link_sgx_uae_service() {
    let _ = *MAYBE_EMIT_LIB_DIR;
    link("dylib", "sgx_epid", sim_postfix());
}

// Used in trusted code.
pub fn link_sgx_tservice() {
    let _ = *MAYBE_EMIT_LIB_DIR;
    link("static", "sgx_tservice", sim_postfix());
}

// Used in untrusted code, counterpart is trts
pub fn link_sgx_urts() {
    let _ = *MAYBE_EMIT_LIB_DIR;
    link("dylib", "sgx_urts", sim_postfix());
}
