// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Edger8r Tool Wrapper

use crate::{conf, tools::assert_path_exists};
use std::{
    convert::TryFrom,
    env::var,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    string::String,
};

// Builder pattern for edger8r tool
#[derive(Clone)]
pub struct Edger8r {
    enclave_name: String,
    edl_path: Option<PathBuf>,
    search_paths: Vec<OsString>, // for convenience, include the `--search-path` flags
}

impl Edger8r {
    /// Set an enclave name. This will be used to generate the EDL filename if edl_path is
    /// unspecified.
    pub fn enclave_name(&mut self, enclave_name: &str) -> &mut Self {
        self.enclave_name = enclave_name.to_owned();
        self
    }

    /// Explicitly set a full path to an existing EDL file.
    pub fn edl(&mut self, enclave_edl: &Path) -> &mut Self {
        assert_path_exists(enclave_edl, "enclave edl");
        self.edl_path = Some(
            enclave_edl
                .to_path_buf()
                .canonicalize()
                .expect("Could not canonicalize EDL path"),
        );
        self
    }

    // A search path for edl files included by ours
    pub fn search_path(&mut self, search_path: &Path) -> &mut Self {
        assert_path_exists(search_path, "enclave edl search path");
        self.search_paths.push("--search-path".into());
        self.search_paths.push(
            search_path
                .to_path_buf()
                .canonicalize()
                .expect("Could not canonicalize EDL path")
                .into(),
        );
        self
    }

    fn do_build(&self, trusted: bool) {
        let edger8r_path = &*conf::SDK_BIN_DIR.join("sgx_edger8r");

        let edl_path = if let Some(edl_path) = &self.edl_path {
            edl_path.clone()
        } else {
            let mut edl_path =
                PathBuf::from(var("CARGO_MANIFEST_DIR").expect("Could not read the manifest dir"));
            edl_path.push(&self.enclave_name);
            edl_path.set_extension("edl");
            let expect_str = format!("Could not canonicalize EDL path {:?}", &edl_path);
            edl_path.canonicalize().expect(&expect_str)
        };

        let output_dir = PathBuf::try_from(var("OUT_DIR").expect("Could not read OUT_DIR"))
            .expect("Could not convert OUT_DIR to PathBuf")
            .canonicalize()
            .expect("Could not canonicalize OUT_DIR path");

        let mut edl_name = edl_path
            .file_stem()
            .expect("Corrupted EDL path")
            .to_str()
            .expect("EDL path contains invalid UTF-8")
            .to_owned();

        if trusted {
            edl_name.push_str("_t");

            let stat = Command::new(edger8r_path)
                .args(&self.search_paths)
                .arg(&"--trusted")
                .arg(&edl_path)
                .arg(&"--trusted-dir")
                .arg(&output_dir)
                .status()
                .expect("Could not start sgx edger8r");
            assert!(stat.success(), "edger8r failed");
        } else {
            edl_name.push_str("_u");

            let stat = Command::new(edger8r_path)
                .args(&self.search_paths)
                .arg(&"--untrusted")
                .arg(&edl_path)
                .arg(&"--untrusted-dir")
                .arg(&output_dir)
                .status()
                .expect("Could not start sgx edger8r");
            assert!(stat.success(), "edger8r failed");
        }

        println!(
            "cargo:rerun-if-changed={}",
            edl_path.into_os_string().into_string().unwrap()
        );

        build_generated_code(&output_dir, &edl_name);
    }

    /// Generate and compile the code which will run inside the enclave using the given EDL.
    pub fn build_trusted(&mut self) -> &mut Self {
        self.do_build(true);
        self
    }

    pub fn build_untrusted(&mut self) -> &mut Self {
        self.do_build(false);
        self
    }

    // Generated trusted code in given output directory
    pub fn trusted(&mut self, output_dir: &Path) -> &mut Self {
        let edger8r_path = &*conf::SDK_BIN_DIR.join("sgx_edger8r");
        let stat = Command::new(edger8r_path)
            .args(&self.search_paths)
            .arg(&"--trusted")
            .arg(self.edl_path.as_ref().expect("no edl file was specified"))
            .arg(&"--trusted-dir")
            .arg(output_dir)
            .status()
            .expect("Could not start sgx edger8r");
        assert!(stat.success(), "edger8r failed");
        self
    }

    // Generated untrusted code in given output directory
    pub fn untrusted(&mut self, output_dir: &Path) -> &mut Self {
        let edger8r_path = &*conf::SDK_BIN_DIR.join("sgx_edger8r");
        let stat = Command::new(edger8r_path)
            .args(&self.search_paths)
            .arg(&"--untrusted")
            .arg(self.edl_path.as_ref().expect("no edl file was specified"))
            .arg(&"--untrusted-dir")
            .arg(output_dir)
            .status()
            .expect("Could not start sgx edger8r");
        assert!(stat.success(), "edger8r failed");
        self
    }
}

impl Default for Edger8r {
    fn default() -> Self {
        let mut result = Self {
            enclave_name: var("CARGO_PKG_NAME").expect("Could not read CARGO_PKG_NAME variable"),
            edl_path: None,
            search_paths: Default::default(),
        };
        result.search_path(&*conf::SDK_INCLUDE_DIR);
        result.search_path(
            &PathBuf::try_from(&var("OUT_DIR").expect("Could not read OUT_DIR variable"))
                .expect("Could not convert OUT_DIR variable to a path")
                .canonicalize()
                .expect("Could not canonicalize OUT_DIR path"),
        );
        result
    }
}

pub fn build_generated_code(source_dir: &Path, source_name: &str) {
    let mut build = cc::Build::new();

    let tool = build.get_compiler();
    if tool.is_like_gnu() || tool.is_like_clang() {
        build.flag_if_supported("-std=c99");
    }

    build.warnings(false);
    build
        .file(source_dir.join(source_name).with_extension("c"))
        .include((*conf::SDK_INCLUDE_DIR).clone())
        .include(&*conf::SDK_INCLUDE_DIR.join("tlibc"))
        .include(source_dir);
    build.compile(source_name);
}
