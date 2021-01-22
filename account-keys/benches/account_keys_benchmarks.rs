// Copyright (c) 2018-2021 The MobileCoin Foundation

use criterion::{criterion_group, criterion_main, Criterion};
use mc_account_keys::AccountKey;
use rand::{rngs::StdRng, SeedableRng};

fn account_keys_benchmarks(c: &mut Criterion) {
    let mut rng: StdRng = SeedableRng::from_seed([100u8; 32]);
    let mut group = c.benchmark_group("AccountKey");

    group.bench_function("::random", |b| {
        b.iter(|| {
            let _account_key = AccountKey::random(&mut rng);
        })
    });

    let account_key = AccountKey::random(&mut rng);

    group.bench_function("::subaddress", |b| {
        b.iter(|| {
            let _public_address = account_key.subaddress(1);
        })
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(100);
    targets = account_keys_benchmarks
}

criterion_main!(benches);
