// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_build_script::Environment;
use mc_util_build_sgx::{SgxEnvironment, SgxMode};

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not parse SGX environment");

    if sgx.sgx_mode() == SgxMode::Simulation {
        cargo_emit::rustc_cfg!("feature=\"sgx-sim\"");
    }
}
