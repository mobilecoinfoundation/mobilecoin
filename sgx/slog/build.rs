// Copyright (c) 2018-2021 The MobileCoin Foundation

fn main() {
    // This is needed because we disable logging in prod
    mc_sgx_build::handle_ias_dev_feature();
}
