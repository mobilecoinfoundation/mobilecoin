use mc_account_keys::{AccountKey, ShortAddressHash};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_test_vectors_definitions::memos::{
    CorrectEncryptedDestinationMemoData, CorrectEncryptedSenderMemoData,
    CorrectEncryptedSenderWithPaymentRequestIdMemoData, IncorrectEncryptedSenderMemoData,
    IncorrectEncryptedSenderWithPaymentRequestIdMemoData,
};
use mc_transaction_std::{
    AuthenticatedSenderMemo, AuthenticatedSenderWithPaymentRequestIdMemo, DestinationMemo,
    SenderMemoCredential,
};
use mc_util_from_random::FromRandom;
use mc_util_test_vector::write_jsonl;

use rand::{rngs::StdRng, SeedableRng};

fn main() {
    write_correct_encrypted_sender_memos();
    write_incorrect_encrypted_sender_memos();

    write_correct_encrypted_destination_memos();
    write_incorrect_encrypted_destination_memos();

    write_correct_encrypted_sender_with_payment_request_id_memos();
    write_incorrect_encrypted_sender_with_payment_request_id_memos();
}

fn write_correct_encrypted_sender_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_destination_sender_memos: Vec<CorrectEncryptedSenderMemoData> =
            Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_credential = SenderMemoCredential::from(&sender_account_key);
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();

            let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);

            let encrypted_sender_memo = AuthenticatedSenderMemo::new(
                &sender_credential,
                recipient_public_address.view_public_key(),
                &tx_public_key,
            );
            let sender_memo_bytes: [u8; 64] = encrypted_sender_memo.clone().into();

            let encrypted_sender_memo_data = CorrectEncryptedSenderMemoData {
                sender_public_address_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                    &sender_public_address.clone(),
                )),
                recipient_view_public_key_hex_raw_bytes: hex::encode(
                    recipient_public_address.view_public_key().to_bytes(),
                ),
                encrypted_sender_memo_hex_raw_bytes: hex::encode(sender_memo_bytes),
            };
            encrypted_destination_sender_memos.push(encrypted_sender_memo_data);
        }

        encrypted_destination_sender_memos
    })
    .expect("Unable to write test vectors");
}

/// Writes sender memos but records the sender as the receiver. This means that
/// if you try to verify the memo it will necessarily fail.
fn write_incorrect_encrypted_sender_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_destination_sender_memos: Vec<IncorrectEncryptedSenderMemoData> =
            Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_credential = SenderMemoCredential::from(&sender_account_key);
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();

            let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);

            let encrypted_sender_memo = AuthenticatedSenderMemo::new(
                &sender_credential,
                recipient_public_address.view_public_key(),
                &tx_public_key,
            );
            let sender_memo_bytes: [u8; 64] = encrypted_sender_memo.clone().into();

            let encrypted_sender_memo_data = IncorrectEncryptedSenderMemoData {
                /// Report the recipient_public_address as the
                /// sender_public_address. This results in a memo that won't be
                /// correct.
                incorrect_sender_public_address_hex_proto_bytes: hex::encode(
                    mc_util_serial::encode(&recipient_public_address.clone()),
                ),
                /// Report the sender's view_public_key as the
                /// recipient_view_public_key.  This results in a memo that
                /// won't be correct.
                incorrect_recipient_view_public_key_hex_raw_bytes: hex::encode(
                    sender_public_address.view_public_key().to_bytes(),
                ),
                encrypted_sender_memo_hex_raw_bytes: hex::encode(sender_memo_bytes),
            };
            encrypted_destination_sender_memos.push(encrypted_sender_memo_data);
        }

        encrypted_destination_sender_memos
    })
    .expect("Unable to write test vectors");
}

fn write_correct_encrypted_destination_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_destination_sender_memos: Vec<CorrectEncryptedDestinationMemoData> =
            Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();
            let recipient_short_address_hash = ShortAddressHash::from(&recipient_public_address);

            let total_outlay = 12u64;
            let fee = 13u64;

            let encrypted_destination_memo =
                DestinationMemo::new(recipient_short_address_hash.clone(), total_outlay, fee)
                    .unwrap();
            let destination_memo_bytes: [u8; 64] = encrypted_destination_memo.clone().into();

            let encrypted_destination_memo_data = CorrectEncryptedDestinationMemoData {
                sender_public_address_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                    &sender_public_address.clone(),
                )),
                recipient_short_address_hash_hex_raw_bytes: hex::encode(<[u8; 16]>::from(
                    recipient_short_address_hash,
                )),
                total_outlay,
                fee,
                encrypted_destination_memo_hex_raw_bytes: hex::encode(destination_memo_bytes),
            };
            encrypted_destination_sender_memos.push(encrypted_destination_memo_data);
        }

        encrypted_destination_sender_memos
    })
    .expect("Unable to write test vectors");
}

fn write_incorrect_encrypted_destination_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_destination_sender_memos: Vec<CorrectEncryptedDestinationMemoData> =
            Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();
            let recipient_short_address_hash = ShortAddressHash::from(&recipient_public_address);

            let total_outlay = 12u64;
            let fee = 13u64;

            let encrypted_destination_memo =
                DestinationMemo::new(recipient_short_address_hash, total_outlay, fee).unwrap();
            let destination_memo_bytes: [u8; 64] = encrypted_destination_memo.clone().into();

            let sender_short_address_hash = ShortAddressHash::from(&sender_public_address);

            let encrypted_destination_memo_data = CorrectEncryptedDestinationMemoData {
                sender_public_address_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                    &recipient_public_address.clone(),
                )),
                recipient_short_address_hash_hex_raw_bytes: hex::encode(<[u8; 16]>::from(
                    sender_short_address_hash,
                )),
                total_outlay,
                fee,
                encrypted_destination_memo_hex_raw_bytes: hex::encode(destination_memo_bytes),
            };
            encrypted_destination_sender_memos.push(encrypted_destination_memo_data);
        }

        encrypted_destination_sender_memos
    })
    .expect("Unable to write test vectors");
}

fn write_correct_encrypted_sender_with_payment_request_id_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_sender_with_payment_request_id_memos: Vec<
            CorrectEncryptedSenderWithPaymentRequestIdMemoData,
        > = Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_credential = SenderMemoCredential::from(&sender_account_key);
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();

            let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);
            let payment_request_id = 23u64;

            let encrypted_sender_with_payment_request_id_memo =
                AuthenticatedSenderWithPaymentRequestIdMemo::new(
                    &sender_credential,
                    recipient_public_address.view_public_key(),
                    &tx_public_key,
                    payment_request_id,
                );
            let sender_with_payment_request_id_memo_bytes: [u8; 64] =
                encrypted_sender_with_payment_request_id_memo.clone().into();

            let encrypted_sender_memo_with_payment_request_id_data =
                CorrectEncryptedSenderWithPaymentRequestIdMemoData {
                    sender_public_address_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                        &sender_public_address.clone(),
                    )),
                    recipient_view_public_key_hex_raw_bytes: hex::encode(
                        recipient_public_address.view_public_key().to_bytes(),
                    ),
                    payment_request_id,
                    encrypted_sender_with_payment_request_id_memo_hex_raw_bytes: hex::encode(
                        sender_with_payment_request_id_memo_bytes,
                    ),
                };
            encrypted_sender_with_payment_request_id_memos
                .push(encrypted_sender_memo_with_payment_request_id_data);
        }

        encrypted_sender_with_payment_request_id_memos
    })
    .expect("Unable to write test vectors");
}

fn write_incorrect_encrypted_sender_with_payment_request_id_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_sender_with_payment_request_id_memos: Vec<
            IncorrectEncryptedSenderWithPaymentRequestIdMemoData,
        > = Vec::new();
        for _ in 0..10 {
            let sender_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let sender_credential = SenderMemoCredential::from(&sender_account_key);
            let sender_public_address = sender_account_key.default_subaddress();

            let recipient_account_key = AccountKey::new(
                &RistrettoPrivate::from_random(&mut rng),
                &RistrettoPrivate::from_random(&mut rng),
            );
            let recipient_public_address = recipient_account_key.default_subaddress();

            let tx_public_key = CompressedRistrettoPublic::from_random(&mut rng);
            let payment_request_id = 23u64;

            let encrypted_sender_with_payment_request_id_memo =
                AuthenticatedSenderWithPaymentRequestIdMemo::new(
                    &sender_credential,
                    recipient_public_address.view_public_key(),
                    &tx_public_key,
                    payment_request_id,
                );
            let sender_with_payment_request_id_memo_bytes: [u8; 64] =
                encrypted_sender_with_payment_request_id_memo.clone().into();

            let encrypted_sender_memo_with_payment_request_id_data =
                IncorrectEncryptedSenderWithPaymentRequestIdMemoData {
                    incorrect_sender_public_address_hex_proto_bytes: hex::encode(
                        mc_util_serial::encode(&recipient_public_address.clone()),
                    ),
                    incorrect_recipient_view_public_key_hex_raw_bytes: hex::encode(
                        sender_public_address.view_public_key().to_bytes(),
                    ),
                    payment_request_id,
                    encrypted_sender_with_payment_request_id_memo_hex_raw_bytes: hex::encode(
                        sender_with_payment_request_id_memo_bytes,
                    ),
                };
            encrypted_sender_with_payment_request_id_memos
                .push(encrypted_sender_memo_with_payment_request_id_data);
        }

        encrypted_sender_with_payment_request_id_memos
    })
    .expect("Unable to write test vectors");
}
