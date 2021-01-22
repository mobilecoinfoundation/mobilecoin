// Copyright (c) 2018-2021 The MobileCoin Foundation

use lazy_static::lazy_static;
use std::{env, path::PathBuf};

// Read environment variables into lazy statics, so that they can be easily
// referred to throughout this crate

lazy_static! {
    // Read SGX_MODE environment variable --set in Docker or makefile
    // Expects values SW and HW
    pub static ref SGX_MODE_SIM: bool = {
        let sgx_mode = env::var("SGX_MODE").expect("Could not read SGX_MODE! Should be HW or SW");
        println!("cargo:rerun-if-env-changed=SGX_MODE");
        if sgx_mode == "SW" {
            println!(
                "cargo:warning=Compiling {} for SGX simulation mode",
                std::env::var("CARGO_PKG_NAME")
                    .expect("Could not get package name from environment")
            );
            true
        } else if sgx_mode == "HW" {
            false
        } else {
            panic!("SGX_MODE should be SW or HW, found {}", sgx_mode);
        }
    };

    // Read IAS_MODE environment variable --set in Docker or makefile
    // Expects values DEV and PROD
    pub static ref IAS_MODE_DEV: bool = {
        let ias_mode = env::var("IAS_MODE").expect("Could not read IAS_MODE! Should be PROD or DEV");
        println!("cargo:rerun-if-env-changed=IAS_MODE");
        if ias_mode == "DEV" {
            println!(
                "cargo:warning=Compiling {} for IAS dev mode",
                std::env::var("CARGO_PKG_NAME")
                    .expect("Could not get package name from environment")
            );
            true
        } else if ias_mode == "PROD" {
            false
        } else {
            panic!("IAS_MODE should be DEV or PROD, found {}", ias_mode);
        }
    };

    // Intel SDK installation dir
    pub static ref SDK_DIR: PathBuf = {
        println!("cargo:rerun-if-env-changed=SGX_SDK");
        PathBuf::from(env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".to_owned()))
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
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR was not set"))
    };

    pub static ref MANIFEST_DIR: PathBuf = {
        PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR was not set"))
    };

    pub static ref RELEASE: bool = {
        env::var("PROFILE").expect("PROFILE was not set") == "release"
    };

    // Other
    pub static ref LD: String = {
        env::var("LD").unwrap_or_else(|_| "ld".to_string())
    };
}
