// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_util_build_script::Environment;

fn main() {
    let env = Environment::default();

    let proto_dir = env.dir().join("proto");
    let proto_str = proto_dir
        .as_os_str()
        .to_str()
        .expect("Invalid UTF-8 in proto dir");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_str);

    let attest_proto_path = env
        .depvar("MC_ATTEST_API_PROTOS_PATH")
        .expect("Could not read attest api's protos path")
        .to_owned();
    let mut all_proto_dirs = attest_proto_path.split(':').collect::<Vec<&str>>();
    all_proto_dirs.push(proto_str);

    let api_proto_path = env
        .depvar("MC_API_PROTOS_PATH")
        .expect("Could not read api's protos path")
        .to_owned();
    all_proto_dirs.extend(api_proto_path.split(':').collect::<Vec<&str>>());

    let consensus_api_proto_path = env
        .depvar("MC_CONSENSUS_API_PROTOS_PATH")
        .expect("Could not read consensus api's protos path")
        .to_owned();
    all_proto_dirs.extend(consensus_api_proto_path.split(':').collect::<Vec<&str>>());

    mc_util_build_grpc::compile_protos_and_generate_mod_rs(
        all_proto_dirs.as_slice(),
        &["report.proto"],
    );
}
