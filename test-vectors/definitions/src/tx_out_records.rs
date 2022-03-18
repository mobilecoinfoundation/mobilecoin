use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with a TxOutRecord that is correct.
pub struct CorrectTxOutRecordData {
    /// The TxOut recipient's view private key bytes encoded in hex.
    pub recipient_view_private_key: String,

    /// The TxOutRecord bytes encoded in hex.
    pub tx_out_record: String,
}

impl TestVector for CorrectTxOutRecordData {
    const FILE_NAME: &'static str = "correct_tx_out_records";
    const MODULE_SUBDIR: &'static str = "tx_out_records";
}
