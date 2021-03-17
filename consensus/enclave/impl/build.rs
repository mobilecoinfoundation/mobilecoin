// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Bake the compile-time target features into the enclave.

use cargo_emit::rerun_if_env_changed;
use mc_util_build_script::Environment;
use std::{env::var, fs};

fn main() {
    let env = Environment::default();

    let mut target_features = env
        .target_features()
        .iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<String>>();
    target_features.sort();

    let mut contents = String::from("const TARGET_FEATURES: &[&str] = &[\n");
    for feature in target_features {
        contents.push_str("    \"");
        contents.push_str(&feature);
        contents.push_str("\",\n");
    }
    contents.push_str("];\n\n");

    let features_out = env.out_dir().join("target_features.rs");

    // Only write if the contents would change.
    if fs::read_to_string(&features_out).ok().as_ref() != Some(&contents) {
        fs::write(&features_out, &contents).expect("Could not write target feature array");
    }

    rerun_if_env_changed!("FEE_SPEND_PUBLIC_KEY");
    rerun_if_env_changed!("FEE_VIEW_PUBLIC_KEY");

    let mut fee_spend_public_key = [0u8; 32];
    let mut fee_view_public_key = [0u8; 32];

    // These public keys are associated with the private key used in the tests for
    // consensus/enclave/impl. These are the hex-encoded public spend and view key
    // bytes.
    let default_fee_spend_pub = "26b507c63124a2f5e940b4fb89e4b2bb0a2078ed0c8e551ad59268b9646ec241";
    let default_fee_view_pub = "5222a1e9ae32d21c23114a5ce6bb39e0cb56aea350d4619d43b1207061b10346";

    // Check for env var and override
    fee_spend_public_key[..].copy_from_slice(
        &hex::decode(
            &var("FEE_SPEND_PUBLIC_KEY").unwrap_or_else(|_| default_fee_spend_pub.to_string()),
        )
        .expect("Failed parsing public spend key."),
    );
    fee_view_public_key[..].copy_from_slice(
        &hex::decode(
            &var("FEE_VIEW_PUBLIC_KEY").unwrap_or_else(|_| default_fee_view_pub.to_string()),
        )
        .expect("Failed parsing public view key."),
    );

    let mut constants =
        "// Copyright (c) 2018-2021 The MobileCoin Foundation\n\n// Auto-generated file\n\n"
            .to_string();
    constants.push_str(&format!(
        "pub const FEE_SPEND_PUBLIC_KEY: [u8; 32] = {:?};\n\n",
        fee_spend_public_key
    ));
    constants.push_str(&format!(
        "pub const FEE_VIEW_PUBLIC_KEY: [u8; 32] = {:?};\n",
        fee_view_public_key
    ));

    // Output directory for generated constants.
    let output_destination = env.out_dir().join("constants.rs");

    // Only write if the contents would change.
    if fs::read_to_string(&output_destination).ok().as_ref() != Some(&constants) {
        fs::write(&output_destination, &constants).expect("Could not write constants.rs");
    }
}
