use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

/// Contains data associated with a TxOutRecord that is correct.
///
/// Specifically, this means that the included view private key owns the
/// TxOutRecord.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrectTxOutRecordData {
    /// The TxOut recipient's view private key's bytes encoded in hex.
    pub recipient_view_private_key: String,

    /// The TxOutRecord bytes encoded in hex.
    pub tx_out_record: String,
}

impl TestVector for CorrectTxOutRecordData {
    const FILE_NAME: &'static str = "correct_tx_out_records";
    const MODULE_SUBDIR: &'static str = "tx_out_records";
}

/// Contains data associated with a TxOutRecord that is "incorrect."
///
/// Specifically, this means that the included view private key is not
/// associated with the TxOutRecord.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncorrectTxOutRecordData {
    /// An unrelated view private key's bytes encoded in hex.
    pub spurious_view_private_key: String,

    /// The TxOutRecord bytes encoded in hex.
    pub tx_out_record: String,
}

impl TestVector for IncorrectTxOutRecordData {
    const FILE_NAME: &'static str = "incorrect_tx_out_records";
    const MODULE_SUBDIR: &'static str = "tx_out_records";
}
