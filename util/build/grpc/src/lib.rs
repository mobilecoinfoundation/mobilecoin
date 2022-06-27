// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use mc_util_build_script::Environment;
use std::{collections::HashMap, fs, path::Path};

/// Compile protobuf files into Rust code, and generate a mod.rs that references
/// all the generated modules.
pub fn compile_protos_and_generate_mod_rs<P: AsRef<Path>>(proto_dirs: &[P], proto_files: &[P]) {
    compile_protos_and_generate_mod_rs_with_externs(proto_dirs, proto_files, [].into())
}

/// Compile protobuf files into Rust code, and generate a mod.rs that references
/// all the generated modules.
pub fn compile_protos_and_generate_mod_rs_with_externs<P: AsRef<Path>>(
    proto_dirs: &[P],
    proto_files: &[P],
    externs: HashMap<String, String>,
) {
    // If the proto files change, we need to re-run.
    proto_dirs
        .iter()
        .for_each(mc_util_build_script::rerun_if_path_changed);

    // Output directory for generated code.
    let env = Environment::default();
    let output_destination = env.out_dir().join("protos-auto-gen");

    // Delete old code and create output directory.
    let _ = fs::remove_dir_all(&output_destination);
    fs::create_dir_all(&output_destination).expect("failed creating output destination");

    // DO NOT MERGE, debug
    println!(
        "cargo:warning=Writing {:?}",
        output_destination.join("mod.rs")
    );

    // Generate code.
    let mut prost_config = prost_build::Config::new();
    prost_config
        .include_file(output_destination.join("mod.rs"))
        .out_dir(&output_destination);
    for (proto_path, rust_path) in externs {
        prost_config.extern_path(proto_path, rust_path);
    }

    grpcio_compiler::prost_codegen::compile_protos_with_config(
        proto_files,
        proto_dirs,
        prost_config,
    )
    .expect("Failed to compile gRPC definitions!");
}
