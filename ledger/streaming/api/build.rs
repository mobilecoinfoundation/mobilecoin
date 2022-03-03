// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_build_script::Environment;

fn main() {
    let env = Environment::default();

    let api_proto_path = env
        .depvar("MC_API_PROTOS_PATH")
        .expect("Could not read mc_api's protos path")
        .to_owned();
    let mut all_proto_dirs: Vec<&str> = api_proto_path.split(':').collect();

    let proto_dir = env.dir().join("proto");
    let proto_dir = proto_dir
        .as_os_str()
        .to_str()
        .expect("Invalid UTF-8 in proto dir");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_dir);
    all_proto_dirs.push(proto_dir);

    mc_util_build_grpc::compile_protos_and_generate_mod_rs(
        &all_proto_dirs,
        &[
            "archive_blocks.proto",
            "quorum_set.proto",
            "streaming_blocks.proto",
        ],
    );
}
