use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AcctPrivKeysFromRootEntropy {
    pub root_entropy: [u8; 32],
    pub view_private_key: [u8; 32],
    pub spend_private_key: [u8; 32],
}

impl TestVector for AcctPrivKeysFromRootEntropy {
    const FILE_NAME: &'static str = "acct_priv_keys_from_root_entropy";
    const MODULE_SUBDIR: &'static str = "account_keys";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcctPrivKeysFromBip39 {
    pub entropy: Vec<u8>,
    pub mnemonic: String,
    pub account_index: u32,
    pub view_private_key: [u8; 32],
    pub spend_private_key: [u8; 32],
}

impl TestVector for AcctPrivKeysFromBip39 {
    const FILE_NAME: &'static str = "acct_priv_keys_from_bip39";
    const MODULE_SUBDIR: &'static str = "account_keys";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DefaultSubaddrKeysFromAcctPrivKeys {
    pub view_private_key: [u8; 32],
    pub spend_private_key: [u8; 32],
    pub subaddress_view_private_key: [u8; 32],
    pub subaddress_spend_private_key: [u8; 32],
    pub subaddress_view_public_key: [u8; 32],
    pub subaddress_spend_public_key: [u8; 32],
}

impl TestVector for DefaultSubaddrKeysFromAcctPrivKeys {
    const FILE_NAME: &'static str = "default_subaddr_keys_from_acct_priv_keys";
    const MODULE_SUBDIR: &'static str = "account_keys";
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubaddrKeysFromAcctPrivKeys {
    pub view_private_key: [u8; 32],
    pub spend_private_key: [u8; 32],
    pub subaddress_index: u64,
    pub subaddress_view_private_key: [u8; 32],
    pub subaddress_spend_private_key: [u8; 32],
    pub subaddress_view_public_key: [u8; 32],
    pub subaddress_spend_public_key: [u8; 32],
}

impl TestVector for SubaddrKeysFromAcctPrivKeys {
    const FILE_NAME: &'static str = "subaddr_keys_from_acct_priv_keys";
    const MODULE_SUBDIR: &'static str = "account_keys";
}
