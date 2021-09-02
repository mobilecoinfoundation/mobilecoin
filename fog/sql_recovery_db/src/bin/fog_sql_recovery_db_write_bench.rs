// Copyright (c) 2018-2021 The MobileCoin Foundation

use mc_common::logger::create_null_logger;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_recovery_db_iface::RecoveryDb;
use mc_fog_sql_recovery_db::SqlRecoveryDb;
use mc_fog_test_infra::db_tests::{random_block, random_kex_rng_pubkey};
use mc_util_from_random::FromRandom;
use rand::thread_rng;
use rand_core::RngCore;
use std::{
    env,
    time::{Duration, Instant},
};

fn main() {
    let database_url = env::var("DATABASE_URL").expect("Missing DATABASE_URL environment variable");
    let db = SqlRecoveryDb::new_from_url(&database_url, create_null_logger())
        .expect("failled connecting to database");
    let mut rng = thread_rng();

    let ingress_key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key, 0).unwrap();

    // e_tx_out_records tests
    let egress_key = random_kex_rng_pubkey(&mut rng);
    let invoc_id = db
        .new_ingest_invocation(None, &ingress_key, &egress_key, 0)
        .unwrap();

    let mut block_index = 0;
    let nanos_in_1_second = Duration::from_secs(1).as_nanos();
    let started_at = Instant::now();
    loop {
        if started_at.elapsed().as_secs() >= 60 {
            break;
        }

        let n_txs = 1 + (rng.next_u32() % 500);
        let (block, records) = random_block(&mut rng, block_index, n_txs as usize);

        let start = Instant::now();
        db.add_block_data(&invoc_id, &block, 0, &records).unwrap();
        let duration = start.elapsed();

        block_index += 1;
        let one_write_duration = duration.as_nanos() / records.len() as u128;
        let writes_per_sec = nanos_in_1_second / one_write_duration;

        println!(
            "#{}, {} nanos for {} txs, interpolated to {}/s",
            block_index,
            duration.as_nanos(),
            records.len(),
            writes_per_sec
        );
    }

    // user_events test.
    /*
    let max_users = 1000000;

    let key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
    let mut invoc_id = db.new_ingest_invocation(&key, 0).unwrap();

    for i in 0..max_users {
        println!("{}", i);
        let keys: Vec<CompressedRistrettoPublic> = (0..10)
            .map(|_| CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng)))
            .collect();
        let user_ids = db.add_users(&keys).unwrap();
        let recs: Vec<_> = user_ids
            .into_iter()
            .map(|user_id| {
                (
                    user_id,
                    fog_test_infra::db_tests::random_kex_rng_nonce(&mut rng),
                )
            })
            .collect();
        db.add_rng_records(&invoc_id, 0, &recs).unwrap();

        // Rotate invocation id every N rng records.
        if i % 10 == 0 {
            let (block, records) = fog_test_infra::db_tests::random_block(&mut rng, i, 10);

            db.add_block_data(&invoc_id, &block, &records).unwrap();

            db.decommission_ingest_invocation(&invoc_id).unwrap();

            let key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
            invoc_id = db.new_ingest_invocation(&key, 0).unwrap();
        }

        // Write a missed block range every N iterations.
        if i % 200 == 0 {
            db.report_missed_block_range(&fog_types::common::BlockRange::new(100 + i, i + 101))
                .unwrap();
        }
    } */

    /*
    // search_user_events test.
    use std::time::{Duration, Instant};
    let (user_pub_keys_map, _) = db
        .get_users_public_view_keys(&fog_sql_recovery_db::UserId::default())
        .unwrap();
    let user_pub_keys: Vec<_> = user_pub_keys_map.values().map(|v| v.clone()).collect();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let num_threads = 100;

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(num_threads + 1));

    for i in 0..num_threads {
        let database_url = database_url.clone();
        let user_pub_keys = user_pub_keys.clone();
        let count = count.clone();

        let c = std::sync::Arc::clone(&barrier);

        std::thread::spawn(move || {
            let mut rng = thread_rng();
            let db =
                SqlRecoveryDb::new_from_url(&database_url).expect("failled connecting to database");
            let nanos_in_1_second = Duration::from_secs(1).as_nanos();

            println!("{} connected", i);
            c.wait();

            println!("loaded {} users", user_pub_keys.len());
            loop {
                let mut key = user_pub_keys[rng.next_u32() as usize % user_pub_keys.len()].clone();
                if i % 2 == 0 {
                    key = CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng));
                }

                let start = Instant::now();
                let (events, _) = db.search_user_events(0, Some(&key)).unwrap();
                let duration = start.elapsed();

                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                let reads_per_sec = nanos_in_1_second / duration.as_nanos();
                /*println!(
                    "{} {:?}: {} events, {}ms, interpolated to {}/s",
                    i,
                    std::thread::current().id(),
                    events.len(),
                    duration.as_nanos() as f64 / 1000000.0,
                    reads_per_sec
                );*/
            }
        });
    }

    barrier.wait();
    println!("SLEEP");
    std::thread::sleep(std::time::Duration::from_secs(60));
    println!("{}", count.load(std::sync::atomic::Ordering::SeqCst));
    */
}
