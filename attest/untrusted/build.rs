// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Build script for attest_trusted, optionally links to libsgx_tservice.a when
//! built on Linux, with the "sgx" feature enabled.

fn main() {
    mc_sgx_build::handle_sgx_sim_feature();
    mc_sgx_build::link_sgx_uae_service();
}
