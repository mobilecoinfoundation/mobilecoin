// Copyright (c) 2018-2021 The MobileCoin Foundation

use cargo_emit::{rustc_link_lib, rustc_link_search};
use pkg_config::Library;
use std::{collections::HashSet, path::Path};

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
            .map(|library| library.include_paths.iter().map(AsRef::<Path>::as_ref))
            .flatten()
            .collect::<HashSet<&Path>>()
    }

    /// Gather all the library search paths together.
    fn link_paths(&self) -> HashSet<&Path> {
        self.iter()
            .map(|library| library.link_paths.iter().map(AsRef::<Path>::as_ref))
            .flatten()
            .collect::<HashSet<&Path>>()
    }

    /// Gather a list of SONAMEs which are used by the libraries
    fn libs(&self) -> HashSet<&str> {
        self.iter()
            .map(|library| library.libs.iter().map(AsRef::<str>::as_ref))
            .flatten()
            .collect::<HashSet<&str>>()
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
