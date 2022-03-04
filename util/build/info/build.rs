// Copyright (c) 2018-2022 The MobileCoin Foundation

use cargo_emit::rerun_if_env_changed;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

/// Get git revision by running `git describe` in a given directory.
fn get_git_commit(current_dir: impl AsRef<Path>) -> String {
    match Command::new("git")
        .args(&["describe", "--always", "--dirty=-modified"])
        .current_dir(current_dir)
        .output()
    {
        Err(err) => {
            eprintln!("Couldn't run git: {}", err);
            "??????".to_string()
        }
        Ok(proc_output) => {
            if !proc_output.status.success() {
                eprintln!(
                    "git describe failed: {}",
                    String::from_utf8(proc_output.stderr.clone()).expect("utf8-error")
                );
                String::from_utf8(proc_output.stderr[0..24].to_vec()).expect("utf8-error")
            } else {
                String::from_utf8(proc_output.stdout)
                    .expect("utf8-error")
                    .trim()
                    .to_string()
            }
        }
    }
}

/// Get the git commit of what should be the root repository.
/// This is useful when `mobilecoin` is a submodule of another repository.
/// Use the GIT_COMMIT environment variable to override this.
fn get_root_git_commit() -> String {
    if let Ok(result) = env::var("GIT_COMMIT") {
        eprintln!("GIT_COMMIT from env: {}", result);
        return result;
    }

    // Traverse up until we can no longer find a git directory.
    let mut current_dir = env::current_dir().expect("failed getting current directory");
    let mut last_git_dir = None;
    loop {
        // See if the current directory contains a .git directory
        if current_dir.join(".git").is_dir() {
            last_git_dir = Some(current_dir.clone());
        }

        // Move up and if we're at the root, we're done
        if !current_dir.pop() {
            break;
        }
    }

    match last_git_dir {
        Some(dir) => {
            eprintln!("Root git commit from: {}", dir.display());
            get_git_commit(dir)
        }
        None => {
            cargo_emit::warning!("could not locate root .git directory");
            "??????".to_string()
        }
    }
}

/// Get the `mobilecoin` repository's git commit.
// This build script is run from the directory containing it, so calling
// get_get_commit with the current directory will give the git commit of the
// mobilecoin repository. When mobilecoin is not submoduled this will be
// identicial to the root git commit returned from `get_root_git_commit`.
fn get_mobilecoin_git_commit() -> String {
    get_git_commit(env::current_dir().expect("failed getting current directory"))
}

/// true if env var exist, false if not
fn env_var_exists(name: &str) -> &'static str {
    rerun_if_env_changed!(name);
    match env::var(name) {
        Ok(_) => "true",
        Err(env::VarError::NotPresent) => "false",
        Err(e) => panic!("{}", e),
    }
}

/// read env var, or fallback
fn env_with_fallback(name: &str, fallback: &str) -> String {
    rerun_if_env_changed!(name);
    env::var(name).unwrap_or_else(|_| fallback.to_string())
}

fn main() {
    // Collect stuff to go in the build info file
    let root_git_commit = get_root_git_commit();
    let mobilecoin_git_commit = get_mobilecoin_git_commit();
    let profile = env_with_fallback("PROFILE", "?");
    let debug = env_with_fallback("DEBUG", "false");
    let opt_level = env_with_fallback("OPT_LEVEL", "?");
    let debug_assertions = env_var_exists("CARGO_CFG_DEBUG_ASSERTIONS").to_string();
    let target_arch = env_with_fallback("CARGO_CFG_TARGET_ARCH", "?");
    let target_os = env_with_fallback("CARGO_CFG_TARGET_OS", "?");
    let target_feature = env_with_fallback("CARGO_CFG_TARGET_FEATURE", "?");
    let rustflags = env_with_fallback("RUSTFLAGS", "?");
    let sgx_mode = env_with_fallback("SGX_MODE", "?");
    let ias_mode = env_with_fallback("IAS_MODE", "?");

    // Format the contents
    let gen_contents = format!(
        r###"
// This file is generated
pub fn git_commit() -> &'static str {{ "{}" }}
pub fn mobilecoin_git_commit() -> &'static str {{ "{}" }}
pub fn profile() -> &'static str {{ "{}" }}
pub fn debug() -> &'static str {{ "{}" }}
pub fn opt_level() -> &'static str {{ "{}" }}
pub fn debug_assertions() -> &'static str {{ "{}" }}
pub fn target_arch() -> &'static str {{ "{}" }}
pub fn target_os() -> &'static str {{ "{}" }}
pub fn target_feature() -> &'static str {{ "{}" }}
pub fn rustflags() -> &'static str {{ "{}" }}
pub fn sgx_mode() -> &'static str {{ "{}" }}
pub fn ias_mode() -> &'static str {{ "{}" }}
// Note: Please update `build-info/src/lib.rs` if you add more stuff
"###,
        root_git_commit,
        mobilecoin_git_commit,
        profile,
        debug,
        opt_level,
        debug_assertions,
        target_arch,
        target_os,
        target_feature,
        rustflags,
        sgx_mode,
        ias_mode
    );

    // Check the current contents and see if they are different
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR environment not set?"));
    let out_file = out_dir.join("build_info_generated.rs");
    println!(
        "cargo:rerun-if-changed={}",
        out_file.clone().into_os_string().into_string().unwrap()
    );
    if let Ok(current_contents) = fs::read_to_string(out_file.clone()) {
        eprintln!("current contents:\n{}", current_contents);
        eprintln!("gen contents:\n{}", gen_contents);
        if current_contents == gen_contents {
            // Early return, don't cause make to rerun everything
            return;
        }
    }

    // rewrite the file
    let mut file = fs::File::create(out_file).expect("File creation");
    use std::io::Write;
    write!(&mut file, "{}", gen_contents).expect("File I/O");
}
