// Copyright (c) 2018-2021 MobileCoin Inc.

use mc_util_build_script::Environment;

fn main() {
    let env = Environment::default();

    let proto_dir = env.dir().join("proto");
    let proto_str = proto_dir
        .as_os_str()
        .to_str()
        .expect("Invalid UTF-8 in proto dir");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_str);

    let all_proto_dirs = vec![proto_str];
    mc_util_build_grpc::compile_protos_and_generate_mod_rs(
        all_proto_dirs.as_slice(),
        &["remote_wallet.proto"],
    );
}
