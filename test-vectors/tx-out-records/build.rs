// Copyright (c) 2018-2022 The MobileCoin Foundation

use mc_account_keys::AccountKey;
use mc_common::ResponderId;
use mc_crypto_keys::RistrettoPrivate;
use mc_fog_ingest_enclave_api::{IngestEnclave, IngestEnclaveInitParams};
use mc_fog_ingest_enclave_impl::SgxIngestEnclave;
use mc_fog_types::{
    ingest::TxsForIngest,
    view::{FogTxOut, TxOutRecord},
};
use mc_fog_view_protocol::UserPrivate;
use mc_oblivious_traits::HeapORAMStorageCreator;
use mc_test_vectors_definitions::tx_out_records::{
    CorrectTxOutRecordData, IncorrectTxOutRecordData,
};
use mc_transaction_core::{fog_hint::FogHint, tokens::Mob, tx::TxOut, Amount, BlockVersion, Token};
use mc_util_from_random::FromRandom;
use mc_util_test_vector::write_jsonl;
use rand::{rngs::StdRng, SeedableRng};

fn main() {
    write_correct_tx_out_records();
    write_incorrect_tx_out_records();
}

fn write_correct_tx_out_records() {
    write_jsonl("../vectors", || {
        let mut correct_tx_out_record_data_set: Vec<CorrectTxOutRecordData> = Vec::new();
        let tx_out_record_data = generate_tx_out_record_data();
        for tx_out_record in &tx_out_record_data.tx_out_records {
            let correct_tx_out_record_data = CorrectTxOutRecordData {
                recipient_view_private_key_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                    &tx_out_record_data.recipient_view_private_key,
                )),
                tx_out_record_hex_proto_bytes: hex::encode(mc_util_serial::encode(tx_out_record)),
            };

            correct_tx_out_record_data_set.push(correct_tx_out_record_data);
        }

        correct_tx_out_record_data_set
    })
    .expect("Unable to write test vectors");
}

fn write_incorrect_tx_out_records() {
    write_jsonl("../vectors", || {
        let mut incorrect_tx_out_record_data_set: Vec<IncorrectTxOutRecordData> = Vec::new();
        let tx_out_record_data = generate_tx_out_record_data();
        for tx_out_record in &tx_out_record_data.tx_out_records {
            let incorrect_tx_out_record_data = IncorrectTxOutRecordData {
                spurious_view_private_key_hex_proto_bytes: hex::encode(mc_util_serial::encode(
                    &tx_out_record_data.spurious_view_private_key,
                )),
                tx_out_record_hex_proto_bytes: hex::encode(mc_util_serial::encode(tx_out_record)),
            };

            incorrect_tx_out_record_data_set.push(incorrect_tx_out_record_data);
        }

        incorrect_tx_out_record_data_set
    })
    .expect("Unable to write test vectors");
}

/// Contains data needed for test vectors related to TxOutRecords.
struct TxOutRecordData {
    /// The generated TxOutRecords.
    pub tx_out_records: Vec<TxOutRecord>,

    /// The view private key that owns the TxOut described by the TxOutRecord.
    pub recipient_view_private_key: RistrettoPrivate,

    /// A view private key that does not own the TxOut described by the
    /// TxOutRecord.
    pub spurious_view_private_key: RistrettoPrivate,
}

fn generate_tx_out_record_data() -> TxOutRecordData {
    let logger = mc_common::logger::create_null_logger();
    let token_id = Mob::ID;
    let mut rng: StdRng = SeedableRng::from_seed([2u8; 32]);
    let mut tx_out_records: Vec<TxOutRecord> = Vec::new();

    let recipient_account = AccountKey::random_with_fog(&mut rng);
    let spurious_account = AccountKey::random_with_fog(&mut rng);
    let enclave = SgxIngestEnclave::<HeapORAMStorageCreator>::new(logger.clone());

    let params = IngestEnclaveInitParams {
        responder_id: ResponderId::default(),
        sealed_key: None,
        desired_capacity: 128,
    };
    enclave.enclave_init(params).unwrap();

    let fog_pubkey = enclave.get_ingress_pubkey().unwrap();
    let recipient_public_address = recipient_account.default_subaddress();
    let tx_outs_for_recipient: Vec<_> = (0..10)
        .map(|_| {
            let tx_private_key = RistrettoPrivate::from_random(&mut rng);
            let e_fog_hint =
                FogHint::from(&recipient_public_address).encrypt(&fog_pubkey, &mut rng);
            TxOut::new(
                BlockVersion::TWO,
                Amount {
                    value: 10,
                    token_id,
                },
                &recipient_account.default_subaddress(),
                &tx_private_key,
                e_fog_hint,
            )
            .unwrap()
        })
        .collect();

    let timestamp = 10;
    let txs_for_ingest = TxsForIngest {
        block_index: 1,
        global_txo_index: 100,
        redacted_txs: tx_outs_for_recipient.clone(),
        timestamp,
    };

    // submit txs to enclave
    let (tx_rows, maybe_kex_rng_pubkey) = enclave.ingest_txs(txs_for_ingest.clone()).unwrap();
    assert!(maybe_kex_rng_pubkey.is_none()); // rng store should not have rotated

    // Check that the right number of txs came back
    assert_eq!(tx_rows.len(), 10);

    // Check that the tx row ciphertexts have the right size
    const EXPECTED_PAYLOAD_SIZE: usize = 237; // The observed tx_row.payload size
    for tx_row in tx_rows.iter() {
        assert_eq!(
                tx_row.payload.len(), EXPECTED_PAYLOAD_SIZE,
                "tx_row payload didnt have expected length, should be constant size for security purposes, so that they are all indistinguishable",
            );
    }
    let recipient_fog_credential = UserPrivate::from(&recipient_account);

    for idx in 0..10 {
        let tx_out_record = recipient_fog_credential
            .decrypt_tx_out_result(tx_rows[idx].payload.clone())
            .unwrap();
        assert_eq!(tx_out_record.block_index, txs_for_ingest.block_index);
        assert_eq!(
            tx_out_record.tx_out_global_index,
            txs_for_ingest.global_txo_index + idx as u64
        );
        assert_eq!(
            tx_out_record.get_fog_tx_out().unwrap(),
            FogTxOut::from(&tx_outs_for_recipient[idx])
        );
        tx_out_records.push(tx_out_record);
    }

    TxOutRecordData {
        tx_out_records,
        recipient_view_private_key: recipient_account.view_private_key().clone(),
        spurious_view_private_key: spurious_account.view_private_key().clone(),
    }
}
