// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK EPID FFI functions

use bindgen::Builder;
use cargo_emit::{rustc_link_lib, rustc_link_search};
use mcbuild_sgx_utils::{SgxEnvironment, SgxMode};
use mcbuild_utils::Environment;

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not read SGX environment");

    let mut header = env.dir().join("include");
    header.push("sgx_uae_epid.h");
    Builder::default()
        .ctypes_prefix("mc_sgx_core_types_sys::ctypes")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .header(
            header
                .into_os_string()
                .into_string()
                .expect("Invalid UTF-8 in path to sgx_quote.h"),
        )
        .use_core()
        // We whitelist only the exact stuff we want, because mcsgx-core-types-sys has the basic
        // stuff
        .whitelist_recursively(false)
        .whitelist_function("sgx_init_quote")
        .whitelist_function("sgx_calc_quote_size")
        .whitelist_function("sgx_get_quote_size")
        .whitelist_function("sgx_get_quote")
        .whitelist_function("sgx_get_extended_epid_group_id")
        .whitelist_function("sgx_report_attestation_status")
        .whitelist_function("sgx_check_update_status")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env.out_dir().join("bindings.rs"))
        .expect("Could not write bindings");

    rustc_link_search!(sgx
        .libdir()
        .as_os_str()
        .to_str()
        .expect("Invalid UTF-8 in SGX link path"));

    if sgx.sgx_mode() == SgxMode::Simulation {
        rustc_link_lib!("sgx_epid_sim");
    } else {
        rustc_link_lib!("sgx_epid");
    }
}
