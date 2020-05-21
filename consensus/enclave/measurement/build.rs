// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script for the consensus_enclave_measurement crate.

use cargo_emit::{rerun_if_env_changed, rustc_cfg};
use mc_util_build_enclave::Builder;
use mc_util_build_script::Environment;
use mc_util_build_sgx::{IasMode, SgxEnvironment, SgxMode, TcsPolicy};
use pkg_config::{Config, Error as PkgConfigError, Library};
use std::{env::var, path::PathBuf};

const SGX_LIBS: &[&str] = &["libsgx_urts", "libsgx_epid"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_urts_sim", "libsgx_epid_sim"];

// Changing this version is a breaking change, you must update the crate version if you do.
const SGX_VERSION: &str = "2.9.101.2";

const CONSENSUS_ENCLAVE_PRODUCT_ID: u16 = 1;
const CONSENSUS_ENCLAVE_SECURITY_VERSION: u16 = 1;
const CONSENSUS_ENCLAVE_NAME: &str = "consensus-enclave";
const CONSENSUS_ENCLAVE_DIR: &str = "../trusted";

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

    let mut builder = Builder::new(
        &env,
        &sgx,
        libraries.as_slice(),
        CONSENSUS_ENCLAVE_NAME,
        CONSENSUS_ENCLAVE_DIR.as_ref(),
    )
    .expect("Could not construct builder");

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_CSS");
    if let Ok(value) = var("CONSENSUS_ENCLAVE_CSS") {
        builder.css(PathBuf::from(&value));
    }

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_UNSIGNED");
    if let Ok(value) = var("CONSENSUS_ENCLAVE_UNSIGNED") {
        builder.unsigned_enclave(PathBuf::from(&value));
    }

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_SIGNED");
    if let Ok(value) = var("CONSENSUS_ENCLAVE_SIGNED") {
        builder.signed_enclave(PathBuf::from(&value));
    }

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_LDS");
    if let Ok(value) = var("CONSENSUS_ENCLAVE_LDS") {
        builder.lds(PathBuf::from(&value));
    }

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_PRIVKEY");
    if let Ok(value) = var("CONSENSUS_ENCLAVE_PRIVKEY") {
        builder.privkey(PathBuf::from(&value));
    }

    rerun_if_env_changed!("CONSENSUS_ENCLAVE_GENDATA");
    rerun_if_env_changed!("CONSENSUS_ENCLAVE_PUBKEY");
    rerun_if_env_changed!("CONSENSUS_ENCLAVE_SIGNATURE");
    if let Ok(gendata) = var("CONSENSUS_ENCLAVE_GENDATA") {
        if let Ok(pubkey) = var("CONSENSUS_ENCLAVE_PUBKEY") {
            if let Ok(signature) = var("CONSENSUS_ENCLAVE_SIGNATURE") {
                builder.catsig(gendata.into(), pubkey.into(), signature.into());
            }
        }
    }

    builder
        .cargo_builder
        .target_dir(env.target_dir().join(CONSENSUS_ENCLAVE_NAME));

    builder
        .config_builder
        .debug(
            sgx.sgx_mode() == SgxMode::Simulation
                || sgx.ias_mode() == IasMode::Development
                || env.profile() != "release",
        )
        .prod_id(CONSENSUS_ENCLAVE_PRODUCT_ID)
        .isv_security_version(CONSENSUS_ENCLAVE_SECURITY_VERSION)
        .tcs_num(32)
        .tcs_min_pool(1)
        .tcs_policy(TcsPolicy::Unbound)
        .stack_max_size(256 * 1024)
        .heap_max_size(128 * 1024 * 1024);

    let _sig = builder
        .build()
        .expect("Failed to extract consensus-enclave signature");
}
