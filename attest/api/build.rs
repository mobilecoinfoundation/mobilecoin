// Copyright (c) 2018-2020 MobileCoin Inc.

use mcbuild_utils::Environment;

fn compile_protos() {
    let env = Environment::default();
    let proto_dir = env.out_dir().join("proto");
    cargo_emit::pair!("PROTOS_PATH", "{}", proto_dir.as_os_str().to_str().expect("Invalid UTF-8 in proto dir path"));

    let proto_root = "./proto";
    let proto_files = ["attest.proto"];
    let output_destination = "src";
    println!("cargo:rerun-if-changed={}", proto_root);
    for file in &proto_files {
        println!("cargo:rerun-if-changed={}/{}", proto_root, file);
    }

    protoc_grpcio::compile_grpc_protos(&proto_files, &[proto_root], output_destination)
        .expect("Failed to compile gRPC definitions!");
}

fn main() {
    compile_protos();
}
