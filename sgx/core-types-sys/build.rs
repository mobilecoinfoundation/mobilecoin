// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK core FFI types

use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    Builder,
};
use mc_util_build_script::Environment;
use mc_util_build_sgx::SgxEnvironment;

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.ends_with("_SIZE") || name.ends_with("_BYTES") {
            Some(IntKind::Custom {
                name: "usize",
                is_signed: false,
            })
        } else if name.starts_with("SGX_KEYSELECT_") || name.starts_with("SGX_KEYPOLICY_") {
            Some(IntKind::U16)
        } else {
            None
        }
    }

    fn item_name(&self, name: &str) -> Option<String> {
        if name == "_status_t" {
            Some("sgx_status_t".to_owned())
        } else if name.starts_with("_sgx_") {
            Some(name[1..].to_owned())
        } else if name.starts_with('_') {
            let mut retval = "sgx".to_owned();
            retval.push_str(name);
            Some(retval)
        } else {
            None
        }
    }
}

fn main() {
    let env = Environment::default();
    let mut sgx = SgxEnvironment::new(&env).expect("Could not read SGX environment");

    // Intel is stingy with their pkg-config support, so we're going to use
    // libsgx_urts to get the right types. We don't do any linkage here, so
    // this is fine.
    sgx.add_library("2.9.101.2", "sgx_urts")
        .expect("Could not add SGX URTS to SGX environment");

    let mut builder = Builder::default()
        .ctypes_prefix("crate::ctypes")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true);

    let mut sgx_h_found = false;
    let mut sgx_eid_h_found = false;

    for path in sgx
        .include_paths()
        .expect("Could not retrieve include paths for SGX libraries")
    {
        if !sgx_h_found {
            let sgx_h_path = path.join("sgx.h");
            if sgx_h_path.exists() {
                builder = builder.header(
                    sgx_h_path
                        .as_os_str()
                        .to_str()
                        .expect("Invalid UTF-8 in path to sgx.h"),
                );
                sgx_h_found = true;
            }
        }

        if !sgx_eid_h_found {
            let sgx_eid_h_path = path.join("sgx_eid.h");
            if sgx_eid_h_path.exists() {
                builder = builder.header(
                    sgx_eid_h_path
                        .as_os_str()
                        .to_str()
                        .expect("Invalid UTF-8 in path to sgx_eid.h"),
                );
                sgx_eid_h_found = true;
            }
        }

        if sgx_h_found && sgx_eid_h_found {
            break;
        }
    }

    if !sgx_h_found || !sgx_eid_h_found {
        panic!("Could not find both sgx.h and sgx_eid.h in our include paths");
    }

    builder
        .parse_callbacks(Box::new(Callbacks))
        .prepend_enum_name(false)
        .use_core()
        .whitelist_recursively(false)
        .whitelist_var("SGX_.*")
        .whitelist_type("_attributes_t")
        .whitelist_type("_key_request_t")
        .whitelist_type("_report_body_t")
        .whitelist_type("_report_t")
        .whitelist_type("_sgx_cpu_svn_t")
        .whitelist_type("_sgx_key_id_t")
        .whitelist_type("_sgx_measurement_t")
        .whitelist_type("_sgx_misc_attribute_t")
        .whitelist_type("_sgx_report_data_t")
        .whitelist_type("_status_t")
        .whitelist_type("_target_info_t")
        .whitelist_type("sgx_config_id_t")
        .whitelist_type("sgx_config_svn_t")
        .whitelist_type("sgx_enclave_id_t")
        .whitelist_type("sgx_isv_svn_t")
        .whitelist_type("sgx_isvext_prod_id_t")
        .whitelist_type("sgx_isvfamily_id_t")
        .whitelist_type("sgx_key_128bit_t")
        .whitelist_type("sgx_mac_t")
        .whitelist_type("sgx_misc_select_t")
        .whitelist_type("sgx_prod_id_t")
        .whitelist_type("sgx_status_t")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env.out_dir().join("bindings.rs"))
        .expect("Could not write bindings");
}
