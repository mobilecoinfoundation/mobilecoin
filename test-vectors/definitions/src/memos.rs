use mc_util_test_vector::TestVector;
use serde::{Deserialize, Serialize};

/// Contains the "correct" data associated with an encrypted sender memo.
///
/// Specifically, this means that we've included the correct sender public
/// address and recipient view public key that corresponds to the encrypted
/// sender memo.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrectEncryptedSenderMemoData {
    /// The transaction sender's public address proto bytes encoded as hex. This
    /// user wrote the sender memo.
    pub sender_public_address: String,

    /// The transaction recipient's view public key raw bytes encoded as hex.
    /// This user received the transaction with the sender memo.
    pub recipient_view_public_key: String,

    /// The encrypted sender memo bytes encoded as hex.
    pub encrypted_sender_memo: String,
}

impl TestVector for CorrectEncryptedSenderMemoData {
    const FILE_NAME: &'static str = "correct_encrypted_sender_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}

/// Contains data associated with an encrypted sender memo that has the wrong
/// sender and recipient data.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncorrectEncryptedSenderMemoData {
    /// A public address's bytes encoded as hex. This address did not write the
    /// sender memo.
    pub incorrect_sender_public_address: String,

    /// A view public key's bytes encoded as hex. This key is not the key that
    /// received the transaction with the sender memo.
    pub incorrect_recipient_view_public_key: String,

    /// An encrypted sender memo's bytes encoded as hex.
    pub encrypted_sender_memo: String,
}

impl TestVector for IncorrectEncryptedSenderMemoData {
    const FILE_NAME: &'static str = "incorrect_encrypted_sender_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}

/// Contains data associated with an encrypted destination memo that has the
/// correct sender and recipient data.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrectEncryptedDestinationMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the destination memo.
    pub sender_public_address: String,

    /// The transaction recipient's short address hash bytes encoded as hex.
    /// This user received the TxOut that this destination memo describes.
    pub recipient_short_address_hash: String,

    /// The sum of all the outlays in the transaction. See destination memo
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

/// Contains data associated with an encrypted destination memo that has
/// incorrect sender and recipient data.
#[derive(Debug, Serialize, Deserialize)]
pub struct IncorrectEncryptedDestinationMemoData {
    /// A public address's bytes encoded as hex. This address did not write the
    /// destination memo.
    pub incorrect_sender_public_address: String,

    /// A short address hash's bytes encoded as hex. This short address hash
    /// does not correspond to the address that received the TxOut that the
    /// destination memo describes.
    pub incorrect_recipient_short_address_hash: String,

    /// The sum of all the outlays in the transaction. See destination memo
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

/// Contains data associated with an encrypted sender with payment request ID
/// memo that has the correct sender and recipient data.
#[derive(Debug, Serialize, Deserialize)]
pub struct CorrectEncryptedSenderWithPaymentRequestIdMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the sender with payment request ID memo.
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

#[derive(Debug, Serialize, Deserialize)]
/// Contains data associated with an encrypted destination memo that has
/// incorrect sender and recipient data.
pub struct IncorrectEncryptedSenderWithPaymentRequestIdMemoData {
    /// The transaction sender's public address bytes encoded as hex. This user
    /// wrote the sender memo.
    pub incorrect_sender_public_address: String,

    /// A view public key's bytes encoded as hex. This key is not the key that
    /// received the transaction with the sender with payment request ID memo.
    pub incorrect_recipient_view_public_key: String,

    /// The payment request ID included in the memo.
    pub payment_request_id: u64,

    /// The encrypted sender with payment request ID memo bytes encoded as hex.
    pub encrypted_sender_with_payment_request_id_memo: String,
}

impl TestVector for IncorrectEncryptedSenderWithPaymentRequestIdMemoData {
    const FILE_NAME: &'static str = "incorrect_encrypted_sender_with_payment_request_id_memos";
    const MODULE_SUBDIR: &'static str = "memos";
}
