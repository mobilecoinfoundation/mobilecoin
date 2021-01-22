// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::conf;
use std::{
    fs::File,
    path::{Path, PathBuf},
    process::Command,
};

pub fn check_path_exists<P: AsRef<Path>>(path: P) -> bool {
    std::fs::metadata(path).is_ok()
}

pub fn assert_path_exists<P: AsRef<Path>>(path: P, description: &str) {
    if !check_path_exists(path.as_ref()) {
        panic!(
            "Can't find expected file '{}': {}",
            description,
            path.as_ref().display()
        );
    }
}

pub fn link_enclave(static_archive: &Path, lds_file: &Path, shared_output: &Path) {
    assert_path_exists(static_archive, "cargo-built rust enclave");
    assert_path_exists(lds_file, "enclave linker script");

    let trts_name = format!("-lsgx_trts{}", crate::libs::sim_postfix());
    let service_name = format!("-lsgx_tservice{}", crate::libs::sim_postfix());

    // Note: Compare with intel's example
    // https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleEnclave/Makefile#L148
    let mut command = Command::new((*conf::LD).clone());
    let stat = command
        .args(&[
            "-o",
            shared_output
                .to_str()
                .expect("Shared object output path contains invalid UTF-8"),
        ])
        .args(&["--no-undefined", "-nostdlib"])
        .arg(format!("-L{}", conf::SDK_LIB_DIR.display()))
        .args(&["--whole-archive", &trts_name, "--no-whole-archive"])
        .args(&[
            "--start-group",
            "-lsgx_tstdc",
            "-lsgx_tcxx",
            "-lsgx_tcrypto",
            &service_name,
            static_archive
                .to_str()
                .expect("Archive input path contains invalid UTF-8"),
            "--end-group",
        ])
        .args(&["-Bstatic", "-Bsymbolic", "--no-undefined"])
        .args(&["-pie", "-eenclave_entry", "--export-dynamic"])
        .args(&["--defsym", "__ImageBase=0"])
        .arg("--gc-sections")
        .arg(format!("--version-script={}", lds_file.to_str().unwrap()))
        .status()
        .expect("Could not run linker");

    assert!(stat.success(), "linker failed");
}

// Read the .dump file and produce .mrenclave and .mrsigner files
pub fn get_mrenclave(dumpfile: &Path) -> (PathBuf, PathBuf) {
    assert_path_exists(dumpfile, ".dump file from sgx signer tool");
    let contents = std::fs::read_to_string(dumpfile).expect("Could not read dumpfile");

    let mrenclave = parse_hex_after(&contents, "metadata->enclave_css.body.enclave_hash.m:");
    let mrsigner = parse_hex_after(&contents, "mrsigner->value:");

    let mrenclave_file = dumpfile.with_extension("mrenclave");
    {
        let mut file = File::create(&mrenclave_file).expect("File creation");
        use std::io::Write;
        write!(&mut file, "{}", mrenclave).expect("File I/O");
    }

    let mrsigner_file = dumpfile.with_extension("mrsigner");
    {
        let mut file = File::create(&mrsigner_file).expect("File creation");
        use std::io::Write;
        write!(&mut file, "{}", mrsigner).expect("File I/O");
    }
    (mrenclave_file, mrsigner_file)
}

// Parse intel's goofy hex format
// Search for a key, then search for 0xAB blocks after it, adding AB to result.
// Keep doing this and consuming whitepsace until the next character is not whitespace or we reach the end
fn parse_hex_after(mut text: &str, key: &str) -> String {
    let mut result = String::new();
    while !text.is_empty() && !text.starts_with(key) {
        text = &text[1..];
    }
    if text.is_empty() {
        panic!("Could not find '{}'", key);
    }
    // Skip key
    text = &text[key.len()..];
    // Skip any whitespace
    for chunk in text.split_ascii_whitespace() {
        if chunk.starts_with("0x") {
            // We got another 0xAB pattern, add AB to result
            result.push_str(&chunk[2..]);
        } else {
            // Got something other than 0x..., we're done
            return result;
        }
    }
    result
}
