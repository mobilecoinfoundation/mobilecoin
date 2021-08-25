// Copyright (c) 2018-2020 MobileCoin Inc.

//! Generate the binding code that lives inside the enclave and link it in.

use cargo_emit::rustc_cfg;
use mc_util_build_script::Environment;
use mc_util_build_sgx::{Edger8r, SgxEnvironment, SgxMode};
use pkg_config::{Config, Error as PkgConfigError, Library};

// This should (for now) match the untrusted bridge code. Eventually if Intel
// cleans up their build, this can use, e.g. libsgx_trts.
const SGX_LIBS: &[&str] = &["libsgx_urts", "libsgx_epid"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_urts_sim", "libsgx_epid_sim"];

// Changing this version is a breaking change, you must update the crate version
// if you do.
const SGX_VERSION: &str = "2.13.103.1";

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not parse SGX environment");

    let mut cfg = Config::new();
    cfg.exactly_version(SGX_VERSION)
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

    let mut edger8r = Edger8r::new(&env, libraries.as_slice()).expect("Could not create linkage");

    for edl_data in [
        "SGX_DEBUG_EDL_SEARCH_PATH",
        "SGX_PANIC_EDL_SEARCH_PATH",
        "SGX_SLOG_EDL_SEARCH_PATH",
        "FOG_OCALL_ORAM_STORAGE_EDL_SEARCH_PATH",
    ]
    .iter()
    {
        for path_str in env
            .depvar(edl_data)
            .expect("Could not read EDL dep var")
            .split(':')
        {
            edger8r.search_path(path_str.as_ref());
        }
    }

    let enclave_edl = env
        .depvar("VIEW_ENCLAVE_EDL_FILE")
        .expect("Could not read EDL file");

    edger8r
        .edl(enclave_edl.as_ref())
        .trusted()
        .generate()
        .expect("Could not generate code")
        .build();
}
