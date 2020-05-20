// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script to generate bindings for the Intel SGX SDK core FFI types

use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    Builder,
};
use cargo_emit::rustc_cfg;
use mc_util_build_script::Environment;
use mc_util_build_sgx::{SgxEnvironment, SgxLibraryCollection, SgxMode};
use pkg_config::{Config, Error as PkgConfigError, Library};

const SGX_LIBS: &[&str] = &["libsgx_epid"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_epid_sim"];

// Changing this version is a breaking change, you must update the crate version if you do.
const SGX_VERSION: &str = "2.9.101.2";

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

    let mut cfg = Config::new();
    cfg.exactly_version(SGX_VERSION)
        .print_system_libs(true)
        .cargo_metadata(false)
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
            let header = path.join("sgx_quote.h");
            if header.exists() {
                Some(header)
            } else {
                None
            }
        })
        .expect("Could not find sgx_quote.h")
        .into_os_string()
        .into_string()
        .expect("Invalid UTF-8 in path to sgx_quote.h");

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
        .parse_callbacks(Box::new(Callbacks))
        .prepend_enum_name(false)
        .use_core()
        // We whitelist only the exact stuff we want, because mcsgx-core-types-sys has the basic
        // stuff
        .whitelist_recursively(false)
        .whitelist_type("sgx_epid_group_id_t")
        .whitelist_type("_spid_t")
        .whitelist_type("_basename_t")
        .whitelist_type("_quote_nonce")
        .whitelist_type("sgx_quote_sign_type_t")
        .whitelist_type("_quote_t")
        .whitelist_type("_platform_info")
        .whitelist_type("_update_info_bit")
        .whitelist_var("SGX_PLATFORM_INFO_SIZE")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(env.out_dir().join("bindings.rs"))
        .expect("Could not write bindings");
}
