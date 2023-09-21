// Copyright (c) 2023 The MobileCoin Foundation

use prost_build::Config;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();

    // Note about `Digestible`. `Digestible` needs to be backwards compatible,
    // meaning fields have to be added to the digest in the same order for all time.
    // Deriving `Digestible` will add fields based on the declaration order.
    // Fortunately prost orders fields based on tag number. This means, as long
    // as someone doesn't break the prost tag numbers or names then,
    // `Digestible` should be stable. There are tests in each of the
    // `convert/<type_name>.rs` files that help ensure the `Digestible` field
    // order stability.
    for t in ["EnclaveReportDataContents", "Quote3", "Collateral"].iter() {
        config.type_attribute(
            t,
            "#[derive(serde::Serialize, serde::Deserialize, Digestible, Eq)]",
        );
    }
    config.compile_protos(&["attest.proto"], &["../../api/proto"])?;
    Ok(())
}
