use core::time::Duration;
use criterion::{criterion_group, criterion_main, Criterion};
use mc_common::ResponderId;
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_rand::McRng;
use mc_fog_ingest_enclave::{IngestSgxEnclave, ENCLAVE_FILE};
use mc_fog_ingest_enclave_api::IngestEnclave;
use mc_fog_test_infra::get_enclave_path;
use mc_util_from_random::FromRandom;
use std::str::FromStr;

fn make_enclave(desired_user_capacity: u64) -> IngestSgxEnclave {
    let (enclave, _seal_key) = IngestSgxEnclave::new(
        get_enclave_path(ENCLAVE_FILE),
        &ResponderId::from_str("127.0.0.1:3040").unwrap(),
        &None,
        desired_user_capacity,
    );
    enclave
}

// Benchmark adding one user to an ingest enclave with max capacity for 1
// million users TODO: Ingest api should exist for adding multiple users with
// one ecall, or we should benchmark this anyways
pub fn ingest_capacity_1mil_add_one_user(criterion: &mut Criterion) {
    let enclave = make_enclave(1024 * 1024);

    let mut rng = McRng {};

    criterion.bench_function("ingest cap 1mil add 1 user", |b| {
        b.iter(|| {
            let user = RistrettoPublic::from_random(&mut rng);
            enclave.add_user(user.into())
        })
    });
}

// Benchmark adding one user to an ingest enclave with max capacity for 16
// million users
pub fn ingest_capacity_8mil_add_one_user(criterion: &mut Criterion) {
    let enclave = make_enclave(8 * 1024 * 1024);

    let mut rng = McRng {};

    criterion.bench_function("ingest cap 8mil add 1 user", |b| {
        b.iter(|| {
            let user = RistrettoPublic::from_random(&mut rng);
            enclave.add_user(user.into())
        })
    });
}

// Benchmark adding one user to an ingest enclave with max capacity for 16
// million users
pub fn ingest_capacity_16mil_add_one_user(criterion: &mut Criterion) {
    let enclave = make_enclave(16 * 1024 * 1024);

    let mut rng = McRng {};

    criterion.bench_function("ingest cap 16mil add 1 user", |b| {
        b.iter(|| {
            let user = RistrettoPublic::from_random(&mut rng);
            enclave.add_user(user.into())
        })
    });
}

criterion_group! {
    name = ingest_capacity_1mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = ingest_capacity_1mil_add_one_user
}
criterion_group! {
    name = ingest_capacity_8mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = ingest_capacity_8mil_add_one_user
}
criterion_group! {
    name = ingest_capacity_16mil;
    config = Criterion::default().measurement_time(Duration::new(10, 0));
    targets = ingest_capacity_16mil_add_one_user
}
criterion_main!(
    ingest_capacity_1mil,
    /* FIXME: This requires enclave heap size which is too large and harms CI times
     * Hold off on this until FOG-39, FOG-146, etc. to use untrusted storage
     *ingest_capacity_8mil,
     *ingest_capacity_16mil */
);
