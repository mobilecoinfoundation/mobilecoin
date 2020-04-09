// Copyright (c) 2018-2020 MobileCoin Inc.

//! SGX Build Utilities

use crate::vars::{ENV_IAS_MODE, ENV_SGX_MODE, ENV_SGX_SDK};
use failure::Fail;
use mcbuild_utils::{Environment, EnvironmentError};
use std::{
    convert::TryFrom,
    env::var,
    path::{Path, PathBuf},
};

/// An enumeration of environment errors which occur when parsing SGX environments
#[derive(Clone, Debug, Fail)]
pub enum SgxEnvironmentError {
    /// The IAS mode is unknown
    #[fail(display = "The IAS mode '{}' is unknown", _0)]
    UnknownIasMode(String),

    /// The SGX mode is unknown
    #[fail(display = "The SGX mode '{}' is unknown", _0)]
    UnknownSgxMode(String),

    /// There was an error reading the underlying environment
    #[fail(display = "Environment error: {}", _0)]
    Environment(EnvironmentError),
}

/// The style of interaction with IAS
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IasMode {
    /// When contacting IAS, use the production API service
    Production,
    /// When contacting IAS, use the development API service
    Development,
}

impl TryFrom<&str> for IasMode {
    type Error = SgxEnvironmentError;

    fn try_from(src: &str) -> Result<Self, Self::Error> {
        match src {
            "PROD" => Ok(IasMode::Production),
            "DEV" => Ok(IasMode::Development),
            other => Err(SgxEnvironmentError::UnknownIasMode(other.to_owned())),
        }
    }
}

/// The type of SGX library linkage
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SgxMode {
    /// Link against hardware-enabled SGX libraries
    Hardware,
    /// Link against SGX simulation libraries
    Simulation,
}

impl TryFrom<&str> for SgxMode {
    type Error = SgxEnvironmentError;

    fn try_from(src: &str) -> Result<Self, Self::Error> {
        match src {
            "HW" => Ok(SgxMode::Hardware),
            "SW" => Ok(SgxMode::Simulation),
            other => Err(SgxEnvironmentError::UnknownSgxMode(other.to_owned())),
        }
    }
}

/// The SGX environment reader structure
#[derive(Clone, Debug)]
pub struct SgxEnvironment {
    dir: PathBuf,
    bindir: PathBuf,
    libdir: PathBuf,
    includedir: PathBuf,
    ias_mode: IasMode,
    sgx_mode: SgxMode,
}

impl SgxEnvironment {
    /// Construct a new SGX environment reader
    pub fn new(env: &Environment) -> Result<Self, SgxEnvironmentError> {
        let dir =
            PathBuf::from(var(ENV_SGX_SDK).unwrap_or_else(|_e| String::from("/opt/intel/sgxsdk")));

        let bindir = {
            let arch_str = match env.target_arch() {
                "x86_64" => "x64",
                "x86" => "x86",
                other => panic!("Unknown target architecture {}", other),
            };

            let mut bindir = dir.join("bin");
            bindir.push(arch_str);
            bindir
        };
        let libdir = {
            let libdir = match env.target_arch() {
                "x86_64" => "lib64",
                "x86" => "lib",
                other => panic!("Unknown target architecture {}", other),
            };

            dir.join(libdir)
        };
        let includedir = dir.join("include");

        // Prioritize feature selection over environment variables.
        let ias_mode = if env.feature("ias-dev") {
            IasMode::Development
        } else {
            IasMode::try_from(
                var(ENV_IAS_MODE)
                    .expect("Could not read IAS_MODE variable")
                    .as_str(),
            )
            .expect("Could not parse the IAS mode")
        };

        let sgx_mode = if env.feature("sgx-sim") {
            SgxMode::Simulation
        } else {
            SgxMode::try_from(
                var(ENV_SGX_MODE)
                    .expect("Could not read SGX_MODE variable")
                    .as_str(),
            )
            .expect("Could not parse the SGX mode")
        };

        Ok(Self {
            dir,
            bindir,
            libdir,
            includedir,
            ias_mode,
            sgx_mode,
        })
    }

    /// Get the SGX SDK directory
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Get the SGX SDK binary directory
    pub fn bindir(&self) -> &Path {
        &self.bindir
    }

    /// Get the SGX SDK library directory
    pub fn libdir(&self) -> &Path {
        &self.libdir
    }

    /// Get the SGX SDK include directory
    pub fn includedir(&self) -> &Path {
        &self.includedir
    }

    /// Get the IAS mode requested
    pub fn ias_mode(&self) -> IasMode {
        self.ias_mode
    }

    /// Get the SGX mode requested
    pub fn sgx_mode(&self) -> SgxMode {
        self.sgx_mode
    }
}
