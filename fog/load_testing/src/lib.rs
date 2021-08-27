// Copyright (c) 2018-2021 The MobileCoin Foundation

use std::{
    env,
    path::{Path, PathBuf},
};

pub mod sig_child_handler;

/// Try to find the binary file, searching in whatever places make sense
/// for our infrastructure.
pub fn get_bin_path(filename: &str) -> PathBuf {
    // First try searching right next to the target, this is for circle-ci
    let maybe_result = env::current_exe()
        .expect("Could not get current exe")
        .with_file_name(filename);
    // Try statting the file
    if std::fs::metadata(&maybe_result).is_ok() {
        return maybe_result;
    }

    // Try searching in /usr/bin, this matches production infrastructure
    let maybe_result = Path::new("/usr/bin/").with_file_name(filename);
    // Try statting the file
    if std::fs::metadata(&maybe_result).is_ok() {
        return maybe_result;
    }

    // When cargo runs the binary, it likely won't be next to the ingest server
    // binary. So we try to find the "target" dir and then search target/release
    // or target/debug
    let project_root = {
        let mut result = env::current_exe().expect("Could not get current exe");
        while result.file_name().expect("No Filename for result") != "target" {
            result = result.parent().expect("No parent for result").to_path_buf();
        }
        result
            .parent()
            .expect("Now no parent for result")
            .to_path_buf()
    };
    let maybe_result = project_root
        .join("target")
        .join(mc_util_build_info::profile())
        .join(filename);

    if std::fs::metadata(&maybe_result).is_ok() {
        return maybe_result;
    }

    panic!(
        "Could not find '{}' in current exe directory, /usr/bin/ or target/{}",
        filename,
        mc_util_build_info::profile()
    );
}
