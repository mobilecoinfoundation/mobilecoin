// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Edger8r Tool Wrapper

use crate::{env::Error as EnvironmentError, libraries::SgxLibraryCollection, utils::get_binary};
use cc::Build;
use displaydoc::Display;
use mc_util_build_script::Environment;
use pkg_config::{Error as PkgConfigError, Library};
use std::{
    borrow::ToOwned,
    io::Error as IoError,
    path::{Path, PathBuf},
    process::Command,
    string::{FromUtf8Error, String},
};

/// Errors which can occur when working with edger8r.
#[derive(Debug, Display)]
pub enum Error {
    /// There was an issue querying pkg-config
    PkgConfig(PkgConfigError),
    /// There was missing data in the environment
    Environment(EnvironmentError),
    /**
     * The given SGX library collection did not allow us to deduce the
     * binary location
     */
    NoBinDir,
    /// The given SGX library collection did not contain any include paths
    NoIncludePaths,
    /// There was an error running the command: {0}
    Io(IoError),
    /// The edger8r command failed, and also printed invalid UTF-8
    Utf8Error,
    /**
     * There was an error generating the code,
     * command:\n{0}\nstdout:\n{0}\n\nstderr:\n{1}
     */
    Generate(String, String, String),
    /// There was an error building the generated code
    Build,
}

impl From<EnvironmentError> for Error {
    fn from(src: EnvironmentError) -> Error {
        Error::Environment(src)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(_src: FromUtf8Error) -> Error {
        Error::Utf8Error
    }
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Error {
        Error::Io(src)
    }
}

impl From<PkgConfigError> for Error {
    fn from(src: PkgConfigError) -> Error {
        Error::PkgConfig(src)
    }
}

/// The type of output for `sgx_edger8r`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum OutputKind {
    /// The instance should output commands for untrusted.
    Untrusted,
    /// The instance should output commands for trusted.
    Trusted,
}

/// Builder pattern wrapper for the edger8r tool.
#[derive(Clone, Debug)]
pub struct Edger8r {
    /// The path to the sgx_edger8r executable.
    edger8r_path: PathBuf,
    /// The manifest directory.
    manifest_dir: PathBuf,
    /// The build output dir.
    out_dir: PathBuf,
    /// The include paths to use when compiling the generated code.
    include_paths: Vec<PathBuf>,
    /// The name of the enclave.
    enclave_name: String,
    /// The path to the primary EDL file for this enclave.
    edl_path: PathBuf,
    /// The EDL search paths.
    search_paths: Vec<PathBuf>,
    /// The type of code to be generated.
    output_kind: OutputKind,
}

impl Edger8r {
    /// Create a new edger8r executor.
    pub fn new(env: &Environment, sgx_libs: &[Library]) -> Result<Self, Error> {
        let mut edl_path = env.dir().join(env.name());
        edl_path.set_extension("edl");

        let edger8r_path = get_binary(env.target_arch(), "sgx_edger8r")?;

        let search_paths = sgx_libs
            .include_paths()
            .iter()
            .map(|path| (*path).to_owned())
            .collect::<Vec<PathBuf>>();
        let mut include_paths = search_paths.clone();

        for path in &search_paths {
            include_paths.push(path.join("tlibc"));
        }

        Ok(Self {
            edger8r_path,
            manifest_dir: env.dir().to_owned(),
            out_dir: env.out_dir().to_owned(),
            include_paths,
            enclave_name: env.name().to_owned(),
            edl_path,
            search_paths,
            output_kind: OutputKind::Untrusted,
        })
    }

    /// Set an enclave name. This will be used to generate the EDL filename if
    /// edl_path is unspecified.
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
        self.search_paths.push(search_path.to_owned());
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
    pub fn generate(&self) -> Result<&Self, Error> {
        let mut command = Command::new(&self.edger8r_path);

        for path in &self.search_paths {
            command.args(&[
                "--search-path",
                path.as_os_str()
                    .to_str()
                    .expect("Invalid UTF-8 in EDL search path"),
            ]);
        }

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

        let output = command.output()?;

        if output.status.success() {
            Ok(self)
        } else {
            Err(Error::Generate(
                format!("{:?}", command),
                String::from_utf8(output.stdout)?,
                String::from_utf8(output.stderr)?,
            ))
        }
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
            .include(&self.manifest_dir);

        for dir in &self.include_paths {
            build.include(dir);
        }

        build.compile(&edl_name);
    }
}
