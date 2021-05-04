// Copyright (c) 2018-2021 The MobileCoin Foundation

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub mod conf;
mod edl;
mod libs;
mod sign;
mod tools;

pub use conf::*;
pub use edl::{build_generated_code, Edger8r};
pub use libs::*;
pub use sign::{SgxConfigBuilder, SgxSign, TcsPolicy};
pub use tools::{get_mrenclave, link_enclave};

/// This structure is used to pass output paths from the "signed" crate to the
/// "measurement" crate.
#[derive(Clone, Debug, Default, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct SignedPaths {
    pub enclave: String,
    pub css_file: String,
    pub dump_file: String,
}

/// This structure is used to pass output paths from the "shared" crate to the
/// "signed" crate.
#[derive(Clone, Debug, Default, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct UnsignedPaths {
    pub enclave: String,
    pub config_xml: String,
    pub dat_file: String,
}

/// This structure is the unified TOML serialization between build stages
#[derive(Clone, Debug, Default, Deserialize, Hash, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PathConfig {
    pub unsigned: Option<UnsignedPaths>,
    pub signed: Option<SignedPaths>,
}

// Conditionally apply sgx-sim feature to current crate based on SGX_MODE
pub fn handle_sgx_sim_feature() {
    if *conf::SGX_MODE_SIM {
        println!("cargo:rustc-cfg=feature=\"sgx-sim\"");
    } else if std::env::var("CARGO_FEATURE_SGX_SIM").is_ok() {
        panic!("sgx-sim feature is set by cargo, but SGX_MODE is HW");
    }
}

// Conditionally apply ias-dev feature to current crate based on IAS_MODE
pub fn handle_ias_dev_feature() {
    if *conf::IAS_MODE_DEV {
        println!("cargo:rustc-cfg=feature=\"ias-dev\"");
    } else if std::env::var("CARGO_FEATURE_IAS_DEV").is_ok() {
        panic!("ias-dev feature is set by cargo, but IAS_MODE is PROD");
    }
}

// Tell cargo to rebuild if any *.rs, *.edl, *.proto, Cargo.toml, Cargo.lock or
// a directory itself in a given path has changed.
pub fn rerun_if_code_changed(dir: &str) {
    for entry in WalkDir::new(dir).into_iter().flatten() {
        if entry.path().components().any(|c| c.as_os_str() == "target") {
            continue;
        }

        if entry.file_type().is_file() {
            if let Some(ext) = entry.path().extension() {
                if ext == "rs" || ext == "edl" || ext == "proto" {
                    println!("cargo:rerun-if-changed={}", entry.path().display());
                    //println!("cargo:warning=Tracking {}", entry.path().display());

                    // If this directory contained a source/edl/proto file, we also want to
                    // rebuild in case a file got added or removed.
                    println!(
                        "cargo:rerun-if-changed={}",
                        entry.path().parent().unwrap().display()
                    );
                }
            }
            let fname = entry.file_name();
            if fname == "Cargo.toml" || fname == "Cargo.lock" {
                println!("cargo:rerun-if-changed={}", entry.path().display());
                //println!("cargo:warning=Tracking {}",
                // entry.path().display());
            }
        }
    }
}

// Deduce CARGO_TARGET_DIR from value of OUT_DIR
// This is a workaround for cargo issue: https://github.com/rust-lang/cargo/issues/5457
// described in github comments there.
pub fn find_target_dir() -> PathBuf {
    let mut result = (*conf::OUT_DIR).clone();
    while let Some(name) = result.file_name() {
        if name.to_str().unwrap() == "target" {
            return result;
        }
        if let Some(parent) = result.parent() {
            result = parent.to_path_buf();
        } else {
            break;
        }
    }
    panic!(
        "Could not find target dir from out dir: {}",
        (*conf::OUT_DIR).display()
    );
}

// Run edger8r over given enclave.edl file.
// (Trusted build.rs)
//
// Put trusted in OUT_DIR
// Put untrusted in MANIFEST_DIR/target/untrusted
// Build trusted part and link it to us
pub fn run_edger8r_and_build_trusted(
    enclave_edl: &Path,
    edl_search_path: &Path,
    untrusted_dir: &Path,
) {
    // create-remove-create the untrusted dir, this makes sure the directory is
    // cleared and that if there is a permissions error, it fails at create step
    // and gives the best error message
    std::fs::create_dir_all(&untrusted_dir)
        .expect("could not create directory for untrusted code-gen");
    std::fs::remove_dir_all(&untrusted_dir)
        .expect("could not remove directory for untrusted code-gen");
    std::fs::create_dir_all(&untrusted_dir)
        .expect("could not create directory for untrusted code-gen");
    // Run edger8r
    edl::Edger8r::default()
        .edl(enclave_edl)
        .search_path(edl_search_path)
        .trusted(&*conf::OUT_DIR)
        .untrusted(&untrusted_dir);
    // Now build trusted
    edl::build_generated_code(&*conf::OUT_DIR, "Enclave_t");
}
