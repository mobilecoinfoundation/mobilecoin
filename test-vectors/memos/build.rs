use mc_account_keys::AccountKey;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate};
use mc_test_vectors_definitions::memos::CorrectEncryptedSenderMemoData;
use mc_transaction_std::{AuthenticatedSenderMemo, SenderMemoCredential};
use mc_util_from_random::FromRandom;
use mc_util_test_vector::write_jsonl;
use mc_util_serial;

use rand::{rngs::StdRng, SeedableRng};


fn main() {
    write_encrypted_sender_memos();
}

fn write_encrypted_sender_memos() {
    write_jsonl("../vectors", || {
        let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
        let mut encrypted_sender_memo_dataset: Vec<CorrectEncryptedSenderMemoData> = Vec::new();
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

            let encrypted_sender_memo =
                AuthenticatedSenderMemo::new(&sender_credential, recipient_public_address.view_public_key(), &tx_public_key);
            let sender_memo_bytes: [u8; 64] = encrypted_sender_memo.clone().into();

            let encrypted_sender_memo_data = CorrectEncryptedSenderMemoData {
                sender_public_address: hex::encode(mc_util_serial::encode(&sender_public_address.clone())),
                recipient_view_public_key: hex::encode(recipient_public_address.view_public_key().to_bytes()),
                encrypted_sender_memo: hex::encode(sender_memo_bytes),
            };
            encrypted_sender_memo_dataset.push(encrypted_sender_memo_data);
        }

        encrypted_sender_memo_dataset
    })
    .expect("Unable to write test vectors");
}
