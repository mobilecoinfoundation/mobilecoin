// Copyright (c) 2018-2021 The MobileCoin Foundation

//! SGX Build Utilities

use crate::vars::{ENV_IAS_MODE, ENV_SGX_MODE};
use displaydoc::Display;
use mc_util_build_script::Environment;
use std::{
    convert::TryFrom,
    env::{var, VarError},
    result::Result as StdResult,
};

/// An enumeration of environment errors which occur when parsing SGX
/// environments
#[derive(Debug, Display)]
pub enum Error {
    /// The IAS mode '{0}' is unknown
    UnknownIasMode(String),

    /// The SGX mode '{0}' is unknown
    UnknownSgxMode(String),

    /// There was an error reading an environment variable: {0}
    Variable(VarError),
}

impl From<VarError> for Error {
    fn from(src: VarError) -> Error {
        Error::Variable(src)
    }
}

type Result<T> = StdResult<T, Error>;

/// The style of interaction with IAS
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IasMode {
    /// When contacting IAS, use the production API service
    Production,
    /// When contacting IAS, use the development API service
    Development,
}

impl TryFrom<&str> for IasMode {
    type Error = Error;

    fn try_from(src: &str) -> Result<Self> {
        match src {
            "PROD" => Ok(IasMode::Production),
            "DEV" => Ok(IasMode::Development),
            other => Err(Error::UnknownIasMode(other.to_owned())),
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
    type Error = Error;

    fn try_from(src: &str) -> Result<Self> {
        match src {
            "HW" => Ok(SgxMode::Hardware),
            "SW" => Ok(SgxMode::Simulation),
            other => Err(Error::UnknownSgxMode(other.to_owned())),
        }
    }
}

/// The SGX environment variable reader structure
#[derive(Clone, Debug)]
pub struct SgxEnvironment {
    ias_mode: IasMode,
    sgx_mode: SgxMode,
}

impl SgxEnvironment {
    /// Construct a new SGX environment reader.
    pub fn new(env: &Environment) -> Result<Self> {
        // Prioritize feature selection over environment variables.
        let ias_mode = if env.feature("ias-dev") {
            IasMode::Development
        } else {
            IasMode::try_from(var(ENV_IAS_MODE)?.as_str())?
        };

        let sgx_mode = if env.feature("sgx-sim") {
            SgxMode::Simulation
        } else {
            SgxMode::try_from(var(ENV_SGX_MODE)?.as_str())?
        };

        Ok(Self { ias_mode, sgx_mode })
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
