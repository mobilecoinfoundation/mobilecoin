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

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted destination memo that has the
/// correct sender and recipient data.
pub struct CorrectEncryptedDestinationMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the destination memo.
    pub sender_public_address: String,

    /// The transaction recipient's view public key bytes encoded as hex. This
    /// user received the TxOut that this  memo describes.
    pub recipient_short_address_hash: String,

    /// The sum of all the outlays in the transaction. See destinatoin memo
    /// documentation for more info.
    pub total_outlay: u64,

    /// The fee for the transaction.
    pub fee: u64,

    /// The encrypted destination memo bytes encoded as hex.
    pub encrypted_destination_memo: String,
}

impl TestVector for CorrectEncryptedDestinationMemoData {
    const FILE_NAME: &'static str = "correct_encrypted_destination_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted destination memo that has
/// incorrect sender and recipient data.
pub struct IncorrectEncryptedDestinationMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the destination memo.
    pub incorrect_sender_public_address: String,

    /// The transaction recipient's view public key bytes encoded as hex. This
    /// user received the TxOut that this  memo describes.
    pub incorrect_recipient_short_address_hash: String,

    /// The sum of all the outlays in the transaction. See destinatoin memo
    /// documentation for more info.
    pub total_outlay: u64,

    /// The fee for the transaction.
    pub fee: u64,

    /// The encrypted destination memo bytes encoded as hex.
    pub encrypted_destination_memo: String,
}

impl TestVector for IncorrectEncryptedDestinationMemoData {
    const FILE_NAME: &'static str = "incorrect_encrypted_destination_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted destination memo that has the 
/// correct sender and recipient data.
pub struct CorrectEncryptedSenderWithPaymentRequestIdMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the sender memo.
    pub sender_public_address: String,

    /// The transaction recipient's view public key bytes encoded as hex. This
    /// user received the transaction with the sender memo.
    pub recipient_view_public_key: String,

    /// The payment request ID included in the memo.
    pub payment_request_id: u64,

    /// The encrypted sender memo bytes encoded as hex.
    pub encrypted_sender_with_payment_request_id_memo: String,
}

impl TestVector for CorrectEncryptedSenderWithPaymentRequestIdMemoData {
    const FILE_NAME: &'static str = "correct_encrypted_sender_with_payment_request_id_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}
