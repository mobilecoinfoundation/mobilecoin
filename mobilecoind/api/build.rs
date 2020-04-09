// Copyright (c) 2018-2020 MobileCoin Inc.

extern crate protoc_grpcio;

fn compile_protos() {
    let proto_root = "./proto";
    let external_proto_dir = "../../consensus/api/proto";
    let proto_files = ["mobilecoind_api.proto"];
    let output_destination = "src";
    println!("cargo:rerun-if-changed={}", proto_root);
    for file in &proto_files {
        println!("cargo:rerun-if-changed={}/{}", proto_root, file);
    }

    protoc_grpcio::compile_grpc_protos(
        &proto_files,
        &[proto_root, external_proto_dir],
        output_destination,
    )
    .expect("Failed to compile gRPC definitions!");
}

fn main() {
    compile_protos();
}
