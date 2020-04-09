// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK core FFI types

use bindgen::Builder;
use mcbuild_utils::Environment;

fn main() {
    let env = Environment::default();

    let mut header = env.dir().join("include");
    header.push("sgx_quote.h");
    Builder::default()
        .ctypes_prefix("mcsgx_core_types_sys::ctypes")
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
        .whitelist_type("sgx_epid_group_id_t")
        .whitelist_type("_spid_t")
        .whitelist_type("sgx_spid_t")
        .whitelist_type("_basename_t")
        .whitelist_type("sgx_basename_t")
        .whitelist_type("_quote_nonce")
        .whitelist_type("sgx_quote_nonce_t")
        .whitelist_type("sgx_quote_sign_type_t")
        .whitelist_type("_quote_t")
        .whitelist_type("sgx_quote_t")
        .whitelist_type("_platform_info")
        .whitelist_type("sgx_platform_info_t")
        .whitelist_type("_update_info_bit")
        .whitelist_type("sgx_update_info_bit_t")
        .whitelist_var("SGX_PLATFORM_INFO_SIZE")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env.out_dir().join("bindings.rs"))
        .expect("Could not write bindings");
}
