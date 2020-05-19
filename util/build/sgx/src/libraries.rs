// Copyright (c) 2018-2020 MobileCoin Inc.

use pkg_config::{Config, Error as PkgConfigError, Library};
use std::{
    collections::{HashMap, HashSet},
    iter::FromIterator,
    path::{Path, PathBuf},
    result::Result as StdResult,
};

pub enum Error {
    DuplicateLibrary,
    PrefixNotFound,
}

type Result<T> = StdResult<T, Error>;

pub struct LibraryCollection(HashMap<String, Library>);

impl LibraryCollection {
    /// Add an SGX library to our environment, by name.
    ///
    /// Adding duplicate libraries will result in [`Error::DuplicateLibrary`].
    pub fn add_library(&mut self, version: &str, libname: &str) -> Result<()> {
        if self.0.contains_key(libname) {
            return Err(Error::DuplicateLibrary);
        }

        let mut cfg = Config::new();
        cfg.exactly_version(version);
        self.0.insert(libname.to_owned(), cfg.probe(libname)?);
        Ok(())
    }

    /// Retrieve the bindir where SGX build utility executables are located.
    pub fn bindir(&self) -> Result<PathBuf> {
        if let Some(mut prefix) = self.0.values().find_map(|lib| {
            if let Some(Some(prefix)) = lib.defines.get("prefix") {
                PathBuf::from_str(prefix).ok()
            } else {
                None
            }
        }) {
            prefix.push("bin");
            prefix.push(&self.target_arch);
            Ok(prefix)
        } else {
            Err(Error::PrefixNotFound)
        }
    }

    /// Retrieve a set of all include paths provided by the selected SGX libraries.
    pub fn include_paths(&self) -> Result<HashSet<&Path>> {
        let retval = HashSet::from_iter(
            self.0
                .values()
                .map(|lib| lib.include_paths.iter().map(AsRef::<Path>::as_ref))
                .flatten()
                .collect::<Vec<&Path>>()
                .into_iter(),
        );
        if retval.is_empty() {
            Err(Error::NoIncludePaths)
        } else {
            Ok(retval)
        }
    }
}
