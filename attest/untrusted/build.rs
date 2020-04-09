// Copyright (c) 2018-2020 MobileCoin Inc.

//! Build script for attest_trusted, optionally links to libsgx_tservice.a when built on Linux,
//! with the "sgx" feature enabled.

use sgx_build;

fn main() {
    sgx_build::handle_sgx_sim_feature();
    sgx_build::link_sgx_uae_service();
}
