// Copyright (c) 2018-2020 MobileCoin Inc.

fn main() {
    // This is needed because there is a unit test that only works in sim mode
    sgx_build::handle_sgx_sim_feature();
}
