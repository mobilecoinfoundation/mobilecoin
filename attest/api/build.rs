// Copyright (c) 2018-2020 MobileCoin Inc.

use mcbuild_utils::Environment;

fn main() {
    let env = Environment::default();
    let proto_dir = env.out_dir().join("proto");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_dir.as_os_str().to_str().expect("Invalid UTF-8 in proto dir path"));

    mc_build_grpc::compile_protos_and_generate_mod_rs(&["./proto"], &["attest.proto"]);
}
