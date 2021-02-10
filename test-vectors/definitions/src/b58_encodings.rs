use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct B58EncodePublicAddressWithoutFog {
    pub view_public_key: [u8; 32],
    pub spend_public_key: [u8; 32],
    pub b58_encoded: String,
}

impl TestVector for B58EncodePublicAddressWithoutFog {
    const FILE_NAME: &'static str = "b58_encode_public_address_without_fog";
    const MODULE_SUBDIR: &'static str = "b58_encodings";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct B58EncodePublicAddressWithFog {
    pub view_public_key: [u8; 32],
    pub spend_public_key: [u8; 32],
    pub fog_report_url: String,
    pub fog_report_id: String,
    pub fog_authority_sig: Vec<u8>,
    pub b58_encoded: String,
}

impl TestVector for B58EncodePublicAddressWithFog {
    const FILE_NAME: &'static str = "b58_encode_public_address_with_fog";
    const MODULE_SUBDIR: &'static str = "b58_encodings";
}
