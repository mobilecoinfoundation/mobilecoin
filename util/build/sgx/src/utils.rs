// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Internal utilities

use pkg_config::Error as PkgConfigError;
use std::path::PathBuf;

pub fn get_binary(target_arch: &str, binary_name: &str) -> Result<PathBuf, PkgConfigError> {
    let mut prefix = PathBuf::from(pkg_config::get_variable("libsgx_launch", "prefix")?);
    prefix.push("bin");
    let target_arch = match target_arch {
        "x86_64" => "x64",
        "x86" => "x86",
        other => other,
    };
    prefix.push(target_arch);
    prefix.push(binary_name);
    Ok(prefix)
}
