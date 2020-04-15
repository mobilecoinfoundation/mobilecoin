// Copyright (c) 2018-2020 MobileCoin Inc.

fn main() {
    mc_build_grpc::compile_protos_and_generate_mod_rs(&["./proto"], &["attest.proto"]);
}
