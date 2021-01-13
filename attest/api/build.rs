// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_build_script::Environment;

fn main() {
    let env = Environment::default();
    let proto_dir = env.dir().join("proto");
    cargo_emit::pair!(
        "PROTOS_PATH",
        "{}",
        proto_dir
            .as_os_str()
            .to_str()
            .expect("Invalid UTF-8 in proto dir path")
    );

    mc_util_build_grpc::compile_protos_and_generate_mod_rs(&["./proto"], &["attest.proto"]);
}
