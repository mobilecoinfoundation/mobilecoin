// Copyright (c) 2018-2021 The MobileCoin Foundation

use core::time::Duration;
use criterion::{criterion_group, criterion_main, Criterion};
use mc_common::ResponderId;
use mc_crypto_rand::{McRng, RngCore};
use mc_fog_lmdb_recovery_db::{clear_recovery_db, init_recovery_db, open_recovery_db};
use mc_fog_test_infra::get_enclave_path;
use mc_fog_types::ETxOutRecord;
use mc_fog_view_enclave::{SgxViewEnclave, ENCLAVE_FILE};
use mc_fog_view_enclave_api::{AddETxOutRecordsRequest, ViewEnclaveApi};
use std::{str::FromStr, sync::Arc, vec};

fn make_enclave(desired_tx_out_capacity: u64) -> SgxViewEnclave {
    let logger = mc_common::logger::create_test_logger("add e_txout bench".into());

    let temp_dir = tempdir::TempDir::new("test_view_enclave").unwrap();
    let db_full_path = temp_dir.path();
    clear_recovery_db(&db_full_path);
    init_recovery_db(&db_full_path, &logger);
    let handle = open_recovery_db(&db_full_path, &logger);

    SgxViewEnclave::new(
        get_enclave_path(ENCLAVE_FILE),
        ResponderId::from_str("127.0.0.1:3050").unwrap(),
        Arc::new(handle),
        desired_tx_out_capacity,
        logger,
    )
}

// Benchmark adding one user to view enclave with max capacity for 1 million
pub fn view_capacity_1mil_add_one_e_txout(criterion: &mut Criterion) {
    let enclave = make_enclave(1024 * 1024);

    let mut req = AddETxOutRecordsRequest {
        block_num: 1,
        records: vec![ETxOutRecord {
            search_key: vec![0u8; 16],
            payload: vec![0u8; 160],
        }],
    };

    criterion.bench_function("view cap 1mil add 1 e_txout", |b| {
        b.iter(|| {
            McRng {}.fill_bytes(&mut req.records[0].search_key[..]);
            enclave.add_records(req.clone())
        })
    });
}

// Benchmark adding one user to view enclave with max capacity for 8 million
pub fn view_capacity_4mil_add_one_e_txout(criterion: &mut Criterion) {
    let enclave = make_enclave(4 * 1024 * 1024);

    let mut req = AddETxOutRecordsRequest {
        block_num: 1,
        records: vec![ETxOutRecord {
            search_key: vec![0u8; 16],
            payload: vec![0u8; 160],
        }],
    };

    criterion.bench_function("view cap 4mil add 1 e_txout", |b| {
        b.iter(|| {
            McRng {}.fill_bytes(&mut req.records[0].search_key[..]);
            enclave.add_records(req.clone())
        })
    });
}

// Benchmark adding one user to view enclave with max capacity for 16 million
pub fn view_capacity_8mil_add_one_e_txout(criterion: &mut Criterion) {
    let enclave = make_enclave(8 * 1024 * 1024);

    let mut records = vec![ETxOutRecord {
        search_key: vec![0u8; 16],
        payload: vec![0u8; 160],
    }];

    criterion.bench_function("view cap 8mil add 1 e_txout", |b| {
        b.iter(|| {
            McRng {}.fill_bytes(&mut records[0].search_key[..]);
            enclave.add_records(records.clone())
        })
    });
}

criterion_group! {
    name = view_capacity_1mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = view_capacity_1mil_add_one_e_txout
}
criterion_group! {
    name = view_capacity_4mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = view_capacity_4mil_add_one_e_txout
}
criterion_group! {
    name = view_capacity_8mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = view_capacity_8mil_add_one_e_txout
}
criterion_main!(
    view_capacity_1mil,
    /* FIXME: This requires enclave heap size which is too large and harms CI times
     * Hold off on this until FOG-145, FOG-146, etc. to use untrusted storage
     *view_capacity_4mil,
     *view_capacity_8mil */
);
