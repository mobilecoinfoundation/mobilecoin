//! Build script to compile the llvm-bolt utility and export its path from the

use mc_util_build_script::Environment;
use std::{env, path::PathBuf};

const BOLT_GIT_REVISION: &str = "0655e9a71f43b3fc6a87e3c9be779dc76bc9efb9";
const BOLT_LLVM_GIT_REV: &str = "f137ed238db11440f03083b1c88b7ffc0f4af65e";

fn download_bolt(env: &Environment) -> Result<(), String> {
    Err("Unimplemented".to_owned())
}

fn compile_bolt(env: &Environment) -> Result<PathBuf, String> {
    Err("Unimplemented".to_owned())
}

fn main() {
    let env = Environment::default();

    let bolt_path = env::var("LLVM_BOLT_SIGNALAPP_PATH").map_or_else(
        |_e| {
            download_bolt(&env).expect("Could not download bolt");
            compile_bolt(&env).expect("Could not build bolt")
        },
        PathBuf::from,
    );

    // TODO: ensure executable gets to the OUT_DIR somehow
}
