// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_util_build_script::Environment;

fn main() {
    let env = Environment::default();

    let proto_dir = env.dir().join("proto");
    let proto_str = proto_dir
        .as_os_str()
        .to_str()
        .expect("Invalid UTF-8 in proto dir");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_str);

    mc_util_build_grpc::compile_protos_and_generate_mod_rs(
        &[proto_str],
        &[
            "blockchain.proto",
            "external.proto",
            "printable.proto",
            "quorum_set.proto",
            "watcher.proto",
        ],
    );
}
