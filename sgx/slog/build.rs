// Copyright (c) 2018-2020 MobileCoin Inc.

fn main() {
    // This is needed because we disable logging in prod
    mc_sgx_build::handle_ias_dev_feature();
}
