// Copyright (c) 2018-2020 MobileCoin Inc.

//! Edger8r Tool Wrapper

use crate::env::SgxEnvironment;
use cc::Build;
use mcbuild_utils::Environment;
use std::{
    borrow::ToOwned,
    ffi::OsString,
    path::{Path, PathBuf},
    process::Command,
    string::String,
};

/// The type of output for `sgx_edger8r`
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum OutputKind {
    /// The instance should output commands for untrusted
    Untrusted,
    /// The instance should output commands for trusted
    Trusted,
}

/// Builder pattern wrapper for the edger8r tool
#[derive(Clone, Debug)]
pub struct Edger8r {
    edger8r_path: PathBuf,
    manifest_dir: PathBuf,
    out_dir: PathBuf,
    include_dir: PathBuf,
    enclave_name: String,
    edl_path: PathBuf,
    search_paths: Vec<OsString>,
    output_kind: OutputKind,
}

impl Edger8r {
    /// Create a new edger8r executor.
    pub fn new(env: &Environment, sgx: &SgxEnvironment) -> Self {
        let mut edl_path = env.dir().join(env.name());
        edl_path.set_extension("edl");

        let mut result = Self {
            edger8r_path: sgx.bindir().join("sgx_edger8r"),
            manifest_dir: env.dir().to_owned(),
            out_dir: env.out_dir().to_owned(),
            include_dir: sgx.includedir().to_owned(),
            enclave_name: env.name().to_owned(),
            edl_path,
            search_paths: Default::default(),
            output_kind: OutputKind::Untrusted,
        };
        result.search_path(env.out_dir());
        result.search_path(sgx.includedir());
        result
    }

    /// Set an enclave name. This will be used to generate the EDL filename if edl_path is
    /// unspecified.
    pub fn enclave_name(&mut self, enclave_name: &str) -> &mut Self {
        self.enclave_name = enclave_name.to_owned();
        self
    }

    /// Explicitly set a full path to an existing EDL file.
    pub fn edl(&mut self, enclave_edl: &Path) -> &mut Self {
        self.edl_path = enclave_edl.to_owned();
        self
    }

    /// Add a search path for edl files included by ours
    pub fn search_path(&mut self, search_path: &Path) -> &mut Self {
        self.search_paths.push("--search-path".into());
        self.search_paths.push(search_path.to_owned().into());
        self
    }

    /// Sets the type of code we should generate to trusted
    pub fn trusted(&mut self) -> &mut Self {
        self.output_kind = OutputKind::Trusted;
        self
    }

    /// Sets the type of code we should generate to untrusted.
    pub fn untrusted(&mut self) -> &mut Self {
        self.output_kind = OutputKind::Untrusted;
        self
    }

    /// Execute Edger8r and generate the code
    pub fn generate(&self) -> &Self {
        let mut command = Command::new(&self.edger8r_path);
        command.args(&self.search_paths);

        if self.output_kind == OutputKind::Trusted {
            command
                .arg(&"--trusted")
                .arg(&self.edl_path)
                .arg(&"--trusted-dir");
        } else {
            command
                .arg(&"--untrusted")
                .arg(&self.edl_path)
                .arg(&"--untrusted-dir");
        }
        command.arg(&self.out_dir.to_str().expect("Invalid UTF-8 in out dir"));

        if !command
            .status()
            .expect("Could not execute edger8r")
            .success()
        {
            panic!("Edger8r return an error code");
        }

        self
    }

    /// Compile and link previously generated source files
    pub fn build(&self) {
        let mut build = Build::new();

        let tool = build.get_compiler();
        if tool.is_like_gnu() || tool.is_like_clang() {
            build.flag_if_supported("-std=c99");
        }

        let mut edl_name = self
            .edl_path
            .file_stem()
            .expect("Corrupted EDL path")
            .to_os_string()
            .into_string()
            .expect("EDL path contains invalid UTF-8");

        if self.output_kind == OutputKind::Trusted {
            edl_name.push_str("_t");
        } else {
            edl_name.push_str("_u");
        }

        build
            .warnings(false)
            .file(self.out_dir.join(&edl_name).with_extension("c"))
            .include(&self.manifest_dir)
            .include(&self.include_dir)
            .include(&self.include_dir.join("tlibc"))
            .compile(&edl_name);
    }
}
