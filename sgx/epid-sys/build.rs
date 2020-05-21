// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK EPID FFI functions

use bindgen::Builder;
use cargo_emit::rustc_cfg;
use mc_util_build_script::Environment;
use mc_util_build_sgx::{SgxEnvironment, SgxLibraryCollection, SgxMode};
use pkg_config::{Config, Error as PkgConfigError, Library};

const SGX_LIBS: &[&str] = &["libsgx_epid"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_epid_sim"];

// Changing this version is a breaking change, you must update the crate version if you do.
const SGX_VERSION: &str = "2.9.101.2";

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not read SGX environment");

    let mut cfg = Config::new();
    cfg.exactly_version(SGX_VERSION)
        .print_system_libs(true)
        .cargo_metadata(true)
        .env_metadata(true);

    let libnames = if sgx.sgx_mode() == SgxMode::Simulation {
        rustc_cfg!("feature=\"sgx-sim\"");
        SGX_SIMULATION_LIBS
    } else {
        SGX_LIBS
    };

    let libraries = libnames
        .iter()
        .map(|libname| cfg.probe(libname))
        .collect::<Result<Vec<Library>, PkgConfigError>>()
        .expect("Could not find SGX libraries, check PKG_CONFIG_PATH variable");

    let header = libraries
        .include_paths()
        .into_iter()
        .find_map(|path| {
            let header = path.join("sgx_uae_epid.h");
            if header.exists() {
                Some(header)
            } else {
                None
            }
        })
        .expect("Could not find sgx_uae_epid.h")
        .into_os_string()
        .into_string()
        .expect("Invalid UTF-8 in path to sgx_uae_epid.h");

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
        .header(header)
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
}
