// Copyright (c) 2018-2022 The MobileCoin Foundation

use lazy_static::lazy_static;
use std::{env, path::PathBuf};

// Read environment variables into lazy statics, so that they can be easily
// referred to throughout this crate

lazy_static! {
    // Read SGX_MODE environment variable --set in Docker or makefile
    // Expects values SW and HW
    pub static ref SGX_MODE_SIM: bool = {
        println!("cargo:rerun-if-env-changed=SGX_MODE");
        let sgx_mode = env::var("SGX_MODE").expect("Could not read SGX_MODE! Should be HW or SW");
        match sgx_mode.as_str() {
            "SW" => true,
            "HW" => false,
            _ => panic!("SGX_MODE should be SW or HW, found {}", sgx_mode)
        }
    };

    // Read IAS_MODE environment variable --set in Docker or makefile
    // Expects values DEV and PROD
    pub static ref IAS_MODE_DEV: bool = {
        println!("cargo:rerun-if-env-changed=IAS_MODE");
        let ias_mode = env::var("IAS_MODE").expect("Could not read IAS_MODE! Should be PROD or DEV");
        match ias_mode.as_str() {
            "DEV" => true,
            "PROD" => false,
            _ => panic!("IAS_MODE should be DEV or PROD, found {}", ias_mode)
        }
    };

    // Intel SDK installation dir
    pub static ref SDK_DIR: PathBuf = {
        println!("cargo:rerun-if-env-changed=SGX_SDK");
        env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_owned()).into()
    };

    // Intel SDK lib dir
    pub static ref SDK_LIB_DIR: PathBuf = {
        // Architecture search path
        let arch_dir = if cfg!(target_arch = "x86_64") {
            "lib64"
        } else if cfg!(target_arch = "x86") {
            "lib"
        } else {
            panic!("Unsupported architecture for sgx")
        };
        SDK_DIR.join(arch_dir)
    };

    // Intel SDK bin dir
    pub static ref SDK_BIN_DIR: PathBuf = {
        // Architecture search path
        let arch_dir = if cfg!(target_arch = "x86_64") {
            "x64"
        } else if cfg!(target_arch = "x86") {
            "x86"
        } else {
            panic!("Unsupported architecture for sgx")
        };
        SDK_DIR.join("bin").join(arch_dir)
    };

    // Intel SDK include dir
    pub static ref SDK_INCLUDE_DIR: PathBuf = SDK_DIR.join("include");

    // Cargo variables
    pub static ref OUT_DIR: PathBuf = {
        PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"))
    };

    pub static ref MANIFEST_DIR: PathBuf = {
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("Missing env.CARGO_MANIFEST_DIR"))
    };

    pub static ref RELEASE: bool = {
        env::var("PROFILE").expect("Missing env.PROFILE") == "release"
    };

    // Other
    pub static ref LD: String = {
        env::var("LD").unwrap_or_else(|_| "ld".to_string())
    };
}
