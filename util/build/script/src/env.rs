// Copyright (c) 2018-2021 The MobileCoin Foundation

//! This module contains a structure wrapping up the build environment.

use crate::vars::*;
use displaydoc::Display;
use std::{
    borrow::ToOwned,
    collections::{hash_map::Iter as HashMapIter, hash_set::Iter as HashSetIter, HashMap, HashSet},
    convert::TryFrom,
    env::{split_paths, var, var_os, vars, VarError},
    num::ParseIntError,
    path::{Path, PathBuf},
    str::FromStr,
};

/// An enumeration of target family types
#[derive(Clone, Copy, Debug)]
pub enum TargetFamily {
    /// The environment is some form of unix
    Unix,
    /// The environment is some form of windows
    Windows,
}

/// An enumeration of errors which can occur while parsing the target family
/// environment variable
#[derive(Clone, Debug, Display)]
pub enum TargetFamilyError {
    /// Unknown family: {0}
    Unknown(String),
}

impl TryFrom<&str> for TargetFamily {
    type Error = TargetFamilyError;

    fn try_from(src: &str) -> Result<TargetFamily, Self::Error> {
        match src {
            "unix" => Ok(TargetFamily::Unix),
            "windows" => Ok(TargetFamily::Windows),
            other => Err(TargetFamilyError::Unknown(other.to_owned())),
        }
    }
}

/// An enumeration of endianness types
#[derive(Clone, Copy, Debug)]
pub enum Endianness {
    /// The target platform is little-endian
    Little,
    /// The target platform is big-endian
    Big,
}

/// An enumeration of errors which can occur while parsing the endianness
/// environment variable
#[derive(Clone, Debug, Display)]
pub enum EndiannessError {
    /// Unknown endianness: {0}
    Unknown(String),
}

impl TryFrom<&str> for Endianness {
    type Error = EndiannessError;

    fn try_from(src: &str) -> Result<Endianness, Self::Error> {
        match src {
            "little" => Ok(Endianness::Little),
            "big" => Ok(Endianness::Big),
            other => Err(EndiannessError::Unknown(other.to_owned())),
        }
    }
}

/// An enumeration of errors which can occur when parsing the build environment
#[derive(Clone, Debug, Display)]
pub enum EnvironmentError {
    /// Environment variable {0} not readable: {1}
    Var(String, VarError),
    /// Endianness error: {0}
    Endianness(EndiannessError),
    /// Target family error: {0}
    TargetFamily(TargetFamilyError),
    /// Could not parse {0}: {1}
    ParseInt(String, ParseIntError),
    /// Output directory badly constructed: {0:?}
    OutDir(PathBuf),
}

impl From<EndiannessError> for EnvironmentError {
    fn from(src: EndiannessError) -> EnvironmentError {
        EnvironmentError::Endianness(src)
    }
}

impl From<TargetFamilyError> for EnvironmentError {
    fn from(src: TargetFamilyError) -> EnvironmentError {
        EnvironmentError::TargetFamily(src)
    }
}

fn read_depvars() -> HashMap<String, String> {
    vars()
        .filter_map(|(mut key, value)| {
            if key.starts_with("DEP_") {
                key.replace_range(.."DEP_".len(), "");
                Some((key, value))
            } else {
                None
            }
        })
        .collect()
}

/// Collect all the cargo features currently set.
fn read_features() -> HashSet<String> {
    vars()
        .filter_map(|(mut key, _value)| {
            if key.starts_with("CARGO_FEATURE_") {
                key.replace_range(.."CARGO_FEATURE_".len(), "");
                while let Some(pos) = key.find('_') {
                    key.replace_range(pos..=pos, "-");
                }
                key.make_ascii_lowercase();
                Some(key)
            } else {
                None
            }
        })
        .collect()
}

/// Parse an integer from a string
fn parse_int_var<T: FromStr<Err = ParseIntError>>(env_var: &str) -> Result<T, EnvironmentError> {
    var(env_var)
        .map_err(|e| EnvironmentError::Var(env_var.to_owned(), e))?
        .parse::<T>()
        .map_err(|e| EnvironmentError::ParseInt(env_var.to_owned(), e))
}

/// Create a pathbuf from the contents of the given environment variable
fn env_to_opt_pathbuf(name: &str) -> Option<PathBuf> {
    var(name).ok().and_then(|v| {
        if v.is_empty() {
            None
        } else {
            Some(PathBuf::from(v))
        }
    })
}

/// A description of the current build environment
#[derive(Clone, Debug)]
pub struct Environment {
    cargo_path: PathBuf,
    out_path: PathBuf,
    features: HashSet<String>,

    // CARGO_MANIFEST_*
    manifest_dir: PathBuf,
    manifest_links: Option<String>,

    // CARGO_PKG_*
    pkg_version: String,
    version_major: u64,
    version_minor: u64,
    version_patch: u64,
    version_pre: Option<String>,
    authors: HashSet<String>,
    name: String,
    description: String,
    homepage: String,
    repository: String,

    // CARGO_CFG_*
    debug_assertions: bool,
    proc_macro: bool,
    target_arch: String,
    target_endian: Endianness,
    target_env: String,
    target_family: TargetFamily,
    target_has_atomic: HashSet<String>,
    target_has_atomic_load_store: HashSet<String>,
    target_os: String,
    target_pointer_width: usize,
    target_thread_local: bool,
    target_vendor: String,
    target_features: HashSet<String>,

    // DEP_<CRATE>_VAR
    depvars: HashMap<String, String>,

    // Other variables
    target: String,
    host: String,
    num_jobs: usize,
    opt_level: usize,
    debug: bool,
    profile: String,
    rustc: PathBuf,
    rustdoc: PathBuf,
    linker: PathBuf,
    locked: bool,

    // Derived variables
    target_dir: PathBuf,
    profile_target_dir: PathBuf,
}

impl Default for Environment {
    fn default() -> Environment {
        Environment::new().expect("Could not read environment")
    }
}

impl Environment {
    /// Construct a new build configuration structure, or die trying.
    pub fn new() -> Result<Environment, EnvironmentError> {
        let out_dir = PathBuf::from(
            var(ENV_OUT_DIR).map_err(|e| EnvironmentError::Var(ENV_OUT_DIR.to_owned(), e))?,
        );
        let target =
            var(ENV_TARGET).map_err(|e| EnvironmentError::Var(ENV_TARGET.to_owned(), e))?;
        let profile =
            var(ENV_PROFILE).map_err(|e| EnvironmentError::Var(ENV_PROFILE.to_owned(), e))?;
        let profile_target_dir = out_dir
            .as_path()
            .ancestors()
            .find(|path| path.ends_with(&target) || path.ends_with(&profile))
            .ok_or_else(|| EnvironmentError::OutDir(out_dir.clone()))?
            .to_owned();
        let target_dir = profile_target_dir
            .parent()
            .ok_or_else(|| EnvironmentError::OutDir(out_dir.clone()))?
            .to_owned();

        let target_has_atomic = var(ENV_CARGO_CFG_TARGET_HAS_ATOMIC)
            .unwrap_or_default()
            .split(',')
            .map(ToOwned::to_owned)
            .collect::<HashSet<String>>();

        let target_has_atomic_load_store = var(ENV_CARGO_CFG_TARGET_HAS_ATOMIC_LOAD_STORE)
            .unwrap_or_default()
            .split(',')
            .map(ToOwned::to_owned)
            .collect::<HashSet<String>>();

        let linker = env_to_opt_pathbuf(ENV_RUSTC_LINKER)
            .or_else(|| env_to_opt_pathbuf(ENV_LD))
            .or_else(|| {
                Some(
                    var_os(ENV_PATH)
                        .and_then(|paths| {
                            split_paths(&paths)
                                .filter_map(|dir| {
                                    let full_path = dir.join("ld");
                                    if full_path.is_file() {
                                        Some(full_path)
                                    } else {
                                        None
                                    }
                                })
                                .next()
                        })
                        .expect("Could not find `ld` in path environment variable"),
                )
            })
            .expect("Could not find linker to use");

        let features = read_features();
        let depvars = read_depvars();

        Ok(Self {
            // CARGO_*
            cargo_path: var(ENV_CARGO)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO.to_owned(), e))?
                .into(),
            locked: var(ENV_CARGO_LOCKED).is_ok(),

            // CARGO_MANIFEST_*
            manifest_dir: var(ENV_CARGO_MANIFEST_DIR)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_MANIFEST_DIR.to_owned(), e))?
                .into(),
            manifest_links: var(ENV_CARGO_MANIFEST_LINKS).ok(),

            // Other variables
            debug: var(ENV_DEBUG).is_ok(),
            host: var(ENV_HOST).map_err(|e| EnvironmentError::Var(ENV_HOST.to_owned(), e))?,
            linker,
            num_jobs: parse_int_var(ENV_NUM_JOBS)?,
            out_path: out_dir,
            opt_level: parse_int_var(ENV_OPT_LEVEL)?,
            profile,
            rustc: var(ENV_RUSTC)
                .map_err(|e| EnvironmentError::Var(ENV_RUSTC.to_owned(), e))?
                .into(),
            rustdoc: var(ENV_RUSTDOC)
                .map_err(|e| EnvironmentError::Var(ENV_RUSTDOC.to_owned(), e))?
                .into(),
            target: var(ENV_TARGET).map_err(|e| EnvironmentError::Var(ENV_TARGET.to_owned(), e))?,

            // CARGO_FEATURE_*
            features,
            // DEP_<crate>_<var>
            depvars,

            // CARGO_PKG_*
            pkg_version: var(ENV_CARGO_PKG_VERSION)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_VERSION.to_owned(), e))?,
            version_major: parse_int_var(ENV_CARGO_PKG_VERSION_MAJOR)?,
            version_minor: parse_int_var(ENV_CARGO_PKG_VERSION_MINOR)?,
            version_patch: parse_int_var(ENV_CARGO_PKG_VERSION_PATCH)?,
            version_pre: match var(ENV_CARGO_PKG_VERSION_PRE) {
                Ok(value) => {
                    if value.is_empty() {
                        None
                    } else {
                        Some(value)
                    }
                }
                Err(VarError::NotPresent) => None,
                Err(other) => {
                    return Err(EnvironmentError::Var(
                        ENV_CARGO_PKG_VERSION_PRE.to_owned(),
                        other,
                    ))
                }
            },
            authors: var(ENV_CARGO_PKG_AUTHORS)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_AUTHORS.to_owned(), e))?
                .split(':')
                .map(ToOwned::to_owned)
                .collect(),
            name: var(ENV_CARGO_PKG_NAME)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_NAME.to_owned(), e))?,
            description: var(ENV_CARGO_PKG_DESCRIPTION)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_DESCRIPTION.to_owned(), e))?,
            homepage: var(ENV_CARGO_PKG_HOMEPAGE)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_HOMEPAGE.to_owned(), e))?,
            repository: var(ENV_CARGO_PKG_REPOSITORY)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_PKG_REPOSITORY.to_owned(), e))?,

            // CARGO_CFG_*
            debug_assertions: var(ENV_CARGO_CFG_DEBUG_ASSERTIONS).is_ok(),
            proc_macro: var(ENV_CARGO_CFG_PROC_MACRO).is_ok(),
            target_arch: var(ENV_CARGO_CFG_TARGET_ARCH)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_ARCH.to_owned(), e))?,
            target_endian: Endianness::try_from(
                var(ENV_CARGO_CFG_TARGET_ENDIAN)
                    .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_ENDIAN.to_owned(), e))?
                    .as_str(),
            )?,
            target_env: var(ENV_CARGO_CFG_TARGET_ENV)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_ENV.to_owned(), e))?,
            target_family: TargetFamily::try_from(
                var(ENV_CARGO_CFG_TARGET_FAMILY)
                    .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_FAMILY.to_owned(), e))?
                    .as_ref(),
            )?,
            target_features: var(ENV_CARGO_CFG_TARGET_FEATURE)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_FEATURE.to_owned(), e))?
                .split(',')
                .map(ToOwned::to_owned)
                .collect(),
            target_has_atomic,
            target_has_atomic_load_store,
            target_os: var(ENV_CARGO_CFG_TARGET_OS)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_OS.to_owned(), e))?,
            target_pointer_width: parse_int_var(ENV_CARGO_CFG_TARGET_POINTER_WIDTH)?,
            target_thread_local: var(ENV_CARGO_CFG_TARGET_THREAD_LOCAL).is_ok(),
            target_vendor: var(ENV_CARGO_CFG_TARGET_VENDOR)
                .map_err(|e| EnvironmentError::Var(ENV_CARGO_CFG_TARGET_VENDOR.to_owned(), e))?,

            // Derived variables
            target_dir,
            profile_target_dir,
        })
    }

    /// Get the path to the cargo executables
    pub fn cargo(&self) -> &Path {
        &self.cargo_path
    }

    /// Get whether cargo was invoked with the `--locked` flag
    pub fn locked(&self) -> bool {
        self.locked
    }

    /// Get a reference to a hash set of enabled cargo features (as
    /// `lower-kebab-case` strings)
    pub fn features(&self) -> HashSetIter<String> {
        self.features.iter()
    }

    /// Get whether a feature is enabled or not.
    ///
    /// Feature names are normalized into `lower-kebab-case` (as opposed to
    /// `UPPER_SNAKE_CASE`).
    pub fn feature(&self, feature: &str) -> bool {
        self.features.contains(feature)
    }

    /// Get a reference to a hash map of variables injected by the current
    /// crate's dependencies
    pub fn depvars(&self) -> HashMapIter<String, String> {
        self.depvars.iter()
    }

    /// Get the contents of a particular depvar, if one is provided.
    pub fn depvar(&self, var: &str) -> Option<&str> {
        self.depvars.get(var).map(String::as_str)
    }

    /// Get the directory where the current `Cargo.toml` resides
    pub fn dir(&self) -> &Path {
        &self.manifest_dir
    }

    /// Get the string contents of this crate's `links` key
    pub fn links(&self) -> Option<&str> {
        self.manifest_links.as_deref()
    }

    /// Get whether debug is enabled on this build
    pub fn debug(&self) -> bool {
        self.debug
    }

    /// Get the hostname of the build
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Get the path to the linker executable being used
    pub fn linker(&self) -> &Path {
        &self.linker
    }

    /// Get the number of jobs which can be run in parallel
    pub fn num_jobs(&self) -> usize {
        self.num_jobs
    }

    /// Get the output directory path
    pub fn out_dir(&self) -> &Path {
        &self.out_path
    }

    /// Get the optimization level
    pub fn opt_level(&self) -> usize {
        self.opt_level
    }

    /// Get the build profile as a string
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Get the path to the rustc compiler being used
    pub fn rustc(&self) -> &Path {
        &self.rustc
    }

    /// Get the path to the rustdoc executable being used
    pub fn rustdoc(&self) -> &Path {
        &self.rustdoc
    }

    /// Get the target triple string
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Get the package version string
    pub fn version(&self) -> &str {
        &self.pkg_version
    }

    /// Get the package version major number
    pub fn version_major(&self) -> u64 {
        self.version_major
    }

    /// Get the package version minor number
    pub fn version_minor(&self) -> u64 {
        self.version_minor
    }

    /// Get the package version patch number
    pub fn version_patch(&self) -> u64 {
        self.version_patch
    }

    /// Get the package version pre-release number
    pub fn version_pre(&self) -> Option<String> {
        self.version_pre.clone()
    }

    /// Get a reference to a hash set of package author strings
    pub fn authors(&self) -> &HashSet<String> {
        &self.authors
    }

    /// Get the name of the package of the current package
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the description of the current package
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the homepage of the current package
    pub fn homepage(&self) -> &str {
        &self.homepage
    }

    /// Get the repository of the current package
    pub fn repository(&self) -> &str {
        &self.repository
    }

    /// Get whether or not debug assertions are enabled in this build
    pub fn debug_assertions(&self) -> bool {
        self.debug_assertions
    }

    /// Get whether or not proc macros are enabled in this build
    pub fn proc_macro(&self) -> bool {
        self.proc_macro
    }

    /// Get the target architecture
    pub fn target_arch(&self) -> &str {
        &self.target_arch
    }

    /// Get the endianness
    pub fn target_endian(&self) -> Endianness {
        self.target_endian
    }

    /// Get the target environment
    pub fn target_env(&self) -> &str {
        &self.target_env
    }

    /// Get the target architecture family
    pub fn target_family(&self) -> TargetFamily {
        self.target_family
    }

    /// Get a reference to the target feature set
    pub fn target_features(&self) -> &HashSet<String> {
        &self.target_features
    }

    /// Get a list of types which support atomic operations on the target
    /// platform
    pub fn target_has_atomic(&self) -> &HashSet<String> {
        &self.target_has_atomic
    }

    /// Get a list of types which support atomic load and store
    pub fn target_has_atomic_load_store(&self) -> &HashSet<String> {
        &self.target_has_atomic_load_store
    }

    /// Get the target OS
    pub fn target_os(&self) -> &str {
        &self.target_os
    }

    /// Get the target pointer width
    pub fn target_pointer_width(&self) -> usize {
        self.target_pointer_width
    }

    /// Get whether thread-local storage is available
    pub fn target_thread_local(&self) -> bool {
        self.target_thread_local
    }

    /// Get the target triple vendor
    pub fn target_vendor(&self) -> &str {
        &self.target_vendor
    }

    /// Get the target directory (i.e. the `--target-dir` flag)
    pub fn target_dir(&self) -> &Path {
        &self.target_dir
    }

    /// Get the profile target directory
    pub fn profile_target_dir(&self) -> &Path {
        &self.profile_target_dir
    }
}
