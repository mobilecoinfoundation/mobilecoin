// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK core FFI types

use bindgen::Builder;
use mcbuild_utils::Environment;

fn main() {
    let env = Environment::default();

    let header = env.dir().join("include");
    let eid_header = header
        .join("sgx_eid.h")
        .into_os_string()
        .into_string()
        .expect("Invalid UTF-8 in path to sgx.h");
    let sgx_header = header
        .join("sgx.h")
        .into_os_string()
        .into_string()
        .expect("Invalid UTF-8 in path to sgx.h");
    Builder::default()
        .ctypes_prefix("crate::ctypes")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .header(eid_header)
        .header(sgx_header)
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
        .whitelist_type("sgx_attributes_t")
        .whitelist_type("sgx_config_id_t")
        .whitelist_type("sgx_config_svn_t")
        .whitelist_type("sgx_cpu_svn_t")
        .whitelist_type("sgx_enclave_id_t")
        .whitelist_type("sgx_isv_svn_t")
        .whitelist_type("sgx_isvext_prod_id_t")
        .whitelist_type("sgx_isvfamily_id_t")
        .whitelist_type("sgx_key_128bit_t")
        .whitelist_type("sgx_key_id_t")
        .whitelist_type("sgx_key_request_t")
        .whitelist_type("sgx_mac_t")
        .whitelist_type("sgx_measurement_t")
        .whitelist_type("sgx_misc_attribute_t")
        .whitelist_type("sgx_misc_select_t")
        .whitelist_type("sgx_prod_id_t")
        .whitelist_type("sgx_target_info_t")
        .whitelist_type("sgx_report_t")
        .whitelist_type("sgx_report_body_t")
        .whitelist_type("sgx_report_data_t")
        .whitelist_type("sgx_status_t")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env.out_dir().join("bindings.rs"))
        .expect("Could not write bindings");
}
