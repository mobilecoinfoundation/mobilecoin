// Copyright (c) 2018-2021 The MobileCoin Foundation

fn main() {
    mc_util_build_grpc::compile_protos_and_generate_mod_rs(
        &["./proto"],
        &["build_info.proto", "health_api.proto", "admin.proto"],
    );
}
