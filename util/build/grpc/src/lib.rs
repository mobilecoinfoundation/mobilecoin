// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use grpcio_compiler::prost_codegen::Generator;
use mc_util_build_script::Environment;
use prost_build::Config;
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

    let mut prost_config = Config::new();
    prost_config.service_generator(Box::new(Generator));
    prost_config.out_dir(output_destination.clone());
    prost_config.btree_map(["."]);
    prost_config
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile_protos(proto_files, proto_dirs)
        .expect("Failed to compile gRPC definitions!");

    // Generate the mod.rs file that includes all the auto-generated code.
    let mod_file_contents = fs::read_dir(&output_destination)
        .expect("failed reading output directory")
        .filter_map(|res| res.map(|e| e.path()).ok())
        .filter_map(|path| {
            if path.extension() == Some(OsStr::new("rs")) {
                // File names with a . in it are invalid rust module names, so replace . with _
                // and use path attribute. Example: misty_swap.v1 becomes the
                // rust module misty_swap_v1
                Some(format!(
                    "#[path = \"{}\"]\npub mod {};",
                    path.file_name().unwrap().to_str().unwrap(),
                    path.file_stem()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .replace('.', "_"),
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
