// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{SgxEnvironment, SgxMode};
use cargo_emit::{rustc_link_arg, rustc_link_lib, rustc_link_search};
use displaydoc::Display;
use pkg_config::{Config, Error as PkgConfigError, Library};
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
};

// Changing this version is a breaking change, you must update the crate version
// if you do.
const SGX_VERSION: &str = "2.15.100.3";
const SGX_LIBS: &[&str] = &["libsgx_urts"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_urts_sim"];

/// An enumeration of builder errors.
#[derive(Debug, Display)]
pub enum Error {
    /// There was an error executing pkg-config
    PkgConfig(PkgConfigError),
}
impl From<PkgConfigError> for Error {
    fn from(src: PkgConfigError) -> Error {
        Error::PkgConfig(src)
    }
}

/// A trait which adds SGX functionality onto a [`Library`] collection.
pub trait SgxLibraryCollection {
    /// Retrieve all the unique include paths for this collection.
    fn include_paths(&self) -> HashSet<&Path>;

    /// Retrieve all the unique linker search paths for this collection.
    fn link_paths(&self) -> HashSet<&Path>;

    /// Retrieve all the unique libraries to link to in this collection.
    fn libs(&self) -> HashSet<&str>;

    /// Emit all the relevant cargo linkage instructions for this collection.
    // This function can be deprecated once we're done with baidu.
    fn emit_cargo(&self);
}

/// A blanket implementation of the SGX libraries collection for a [`Library`]
/// slice.
impl SgxLibraryCollection for [Library] {
    /// Gather the include paths for all the include libraries together.
    fn include_paths(&self) -> HashSet<&Path> {
        self.iter()
            .flat_map(|library| library.include_paths.iter().map(PathBuf::as_path))
            .collect()
    }

    /// Gather all the library search paths together.
    fn link_paths(&self) -> HashSet<&Path> {
        self.iter()
            .flat_map(|library| library.link_paths.iter().map(PathBuf::as_path))
            .collect()
    }

    /// Gather a list of SONAMEs which are used by the libraries
    fn libs(&self) -> HashSet<&str> {
        self.iter()
            .flat_map(|library| library.libs.iter().map(String::as_str))
            .collect()
    }

    /// Emit the relevant instructions to cargo to link the current rust crate
    /// with all the contained libraries.
    fn emit_cargo(&self) {
        for library in self {
            for link in &library.libs {
                rustc_link_lib!(link);
            }

            for link_path in &library.link_paths {
                rustc_link_search!(link_path.display());
            }
        }
    }
}

/// Provides the necessary linker flags to link SGX libraries to the crate being
/// built.
///
/// # Arguments
///
/// * `sgx` - The SGX environment for the current build.  This helps to determine if one needs to
///     link to sim or hw libraries.
///
pub fn link_to_sgx_libraries(sgx: &SgxEnvironment) -> Result<(), Error> {
    let mut config = Config::new();
    config
        .exactly_version(SGX_VERSION)
        .print_system_libs(true)
        .cargo_metadata(false)
        .env_metadata(true);
    let lib_paths = if sgx.sgx_mode() == SgxMode::Simulation {
        SGX_SIMULATION_LIBS
    } else {
        SGX_LIBS
    }
    .iter()
    .map(|libname| Ok(config.probe(libname)?.link_paths))
    .collect::<Result<Vec<Vec<PathBuf>>, PkgConfigError>>()?
    .into_iter()
    .flatten()
    .collect::<HashSet<PathBuf>>();

    for path in lib_paths {
        if sgx.sgx_mode() == SgxMode::Simulation {
            let cve_load = path.join("cve_2020_0551_load");
            if cve_load.exists() {
                rustc_link_search!(cve_load.display());
            }
        }
        rustc_link_search!(path.display());
    }

    let sim_postfix = match sgx.sgx_mode() {
        SgxMode::Hardware => "",
        SgxMode::Simulation => "_sim",
    };

    // These need to be linked after the rest of the code so can't use the
    // `rustc_lib_arg`
    rustc_link_arg!("--whole-archive", 
        &format!("-lsgx_trts{}", sim_postfix),
        "--no-whole-archive",
        "-lsgx_tcxx",
        "-lsgx_tcrypto",
        &format!("-lsgx_tservice{}", sim_postfix),
        "-lsgx_tstdc");

    Ok(())
}