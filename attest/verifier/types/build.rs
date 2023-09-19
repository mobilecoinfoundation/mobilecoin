// Copyright (c) 2023 The MobileCoin Foundation

fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(&["attest.proto"], &["../../api/proto"])?;
    Ok(())
}
