// Copyright (c) 2018-2022 The MobileCoin Foundation

fn main() {
    // This is needed because we disable logging in prod
    mc_sgx_build::handle_ias_dev_feature();
}
