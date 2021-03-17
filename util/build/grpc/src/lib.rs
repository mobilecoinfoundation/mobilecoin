// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../README.md")]

use mc_util_build_script::Environment;
use std::{ffi::OsStr, fs, path::PathBuf};

/// Compile protobuf files into Rust code, and generate a mod.rs that references
/// all the generated modules.
pub fn compile_protos_and_generate_mod_rs(proto_dirs: &[&str], proto_files: &[&str]) {
    let env = Environment::default();

    // Output directory for genereated code.
    let output_destination = env.out_dir().join("protos-auto-gen");

    // If the proto files change, we need to re-run.
    for dir in proto_dirs.iter() {
        mc_util_build_script::rerun_if_path_changed(&PathBuf::from(dir));
    }

    // Delete old code and create output directory.
    let _ = fs::remove_dir_all(&output_destination);
    fs::create_dir_all(&output_destination).expect("failed creating output destination");

    // Generate code.
    protoc_grpcio::compile_grpc_protos(proto_files, proto_dirs, &output_destination, None)
        .expect("Failed to compile gRPC definitions!");

    // Generate the mod.rs file that includes all the auto-generated code.
    let mod_file_contents = fs::read_dir(&output_destination)
        .expect("failed reading output directory")
        .filter_map(|res| res.map(|e| e.path()).ok())
        .filter_map(|path| {
            if path.extension() == Some(&OsStr::new("rs")) {
                Some(format!(
                    "pub mod {};",
                    path.file_stem().unwrap().to_str().unwrap()
                ))
            } else {
                None
            }
        })
        .collect::<Vec<String>>()
        .join("\n");

    let mod_file_path = output_destination.join("mod.rs");

    if fs::read_to_string(&mod_file_path).ok().as_ref() != Some(&mod_file_contents) {
        fs::write(&mod_file_path, &mod_file_contents).expect("Failed writing mod.rs");
    }
}
