// Copyright (c) 2018-2020 MobileCoin Inc.

//! Generate the binding code that lives inside the enclave and link it in.

use cargo_emit::rustc_cfg;
use mc_util_build_script::Environment;
use mc_util_build_sgx::{Edger8r, SgxEnvironment, SgxMode};

fn main() {
    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not read SGX build environment");

    if sgx.sgx_mode() == SgxMode::Simulation {
        rustc_cfg!("feature=\"sgx-sim\"");
    }

    let mut edger8r = Edger8r::new(&env, &sgx);

    for edl_data in [
        "SGX_BACKTRACE_EDL_SEARCH_PATH",
        "SGX_DEBUG_EDL_SEARCH_PATH",
        "SGX_PANIC_EDL_SEARCH_PATH",
        "SGX_SLOG_EDL_SEARCH_PATH",
    ]
    .iter()
    {
        for path_str in env
            .depvar(edl_data)
            .expect("Could not read EDL dep var")
            .split(':')
        {
            edger8r.search_path(path_str.as_ref());
        }
    }

    let enclave_edl = env
        .depvar("CONSENSUS_ENCLAVE_EDL_FILE")
        .expect("Could not read EDL file");

    edger8r
        .edl(enclave_edl.as_ref())
        .trusted()
        .generate()
        .build();
}
