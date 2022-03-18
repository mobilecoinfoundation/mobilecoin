use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted sender memo.
pub struct CorrectEncryptedSenderMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the sender memo.
    pub sender_public_address: String,

    /// The transaction recipient's view public key bytes encoded as hex. This
    /// user received the transaction with the sender memo.
    pub recipient_view_public_key: String,

    /// The encrypted sender memo bytes encoded as hex.
    pub encrypted_sender_memo: String,
}

impl TestVector for CorrectEncryptedSenderMemoData {
    const FILE_NAME: &'static str = "correct_encrypted_sender_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted sender memo that has the wrong
/// sender and recipient data.
pub struct IncorrectEncryptedSenderMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the sender memo.
    pub incorrect_sender_public_address: String,

    /// The transaction recipient's view public key bytes encoded as hex. This
    /// user received the transaction with the sender memo.
    pub incorrect_recipient_view_public_key: String,

    /// The encrypted sender memo bytes encoded as hex.
    pub encrypted_sender_memo: String,
}

impl TestVector for IncorrectEncryptedSenderMemoData {
    const FILE_NAME: &'static str = "incorrect_encrypted_sender_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}
