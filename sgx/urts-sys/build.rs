// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK URTS FFI functions

use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    Builder,
};
use cargo_emit::{rustc_link_lib, rustc_link_search};
use mc_util_build_script::Environment;
use mc_util_build_sgx::{SgxEnvironment, SgxMode};

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.ends_with("_SIZE") || name.ends_with("_BYTES") {
            Some(IntKind::Custom {
                name: "usize",
                is_signed: false,
            })
        } else {
            None
        }
    }

    fn item_name(&self, name: &str) -> Option<String> {
        if name.starts_with("_sgx_") {
            Some(name[1..].to_owned())
        } else if name.starts_with('_') {
            let mut retval = "sgx".to_owned();
            retval.push_str(name);
            // Cleanup the _quote_nonce, _platform_info, and _update_info_bit types.
            //
            // Yelling in the wilderness:
            //
            // Is there someone going around teaching students that "`_t` means it's a C type"
            // without further explanation? The `_t` suffix exists for POSIX to namespace itself
            // from the code of mere mortals, not for every damned fool to remind themselves what
            // language they are writing code for.
            //   -jmc
            if !name.ends_with("_t") {
                retval.push_str("_t")
            }

            Some(retval)
        } else {
            None
        }
    }
}

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not read SGX environment");

    let mut header = env.dir().join("include");
    header.push("sgx_urts.h");

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
        .parse_callbacks(Box::new(Callbacks))
        .use_core()
        // We whitelist only the exact stuff we want
        .whitelist_recursively(false)
        .whitelist_function("sgx_create_enclave")
        .whitelist_function("sgx_create_enclave_ex")
        .whitelist_function("sgx_create_enclave_from_buffer_ex")
        .whitelist_function("sgx_create_encrypted_enclave")
        .whitelist_function("sgx_destroy_enclave")
        .whitelist_function("sgx_get_target_info")
        .whitelist_var("MAX_EX_FEATURES_COUNT")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_PCL")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_SWITCHLESS_BIT_IDX")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_SWITCHLESS")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_KSS_BIT_IDX")
        .whitelist_var("SGX_CREATE_ENCLAVE_EX_KSS")
        .whitelist_type("_sgx_kss_config_t")
        .whitelist_type("sgx_launch_token_t")
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
        rustc_link_lib!("sgx_urts_sim");
    } else {
        rustc_link_lib!("sgx_urts");
    }
}
