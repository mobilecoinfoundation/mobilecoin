// Copyright (c) 2018-2021 The MobileCoin Foundation

// Exercise report server grpc APIs and check for expected behavior

use grpcio::ChannelBuilder;
use mc_attest_core::VerificationReport;
use mc_common::logger::{test_with_logger, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_api::{report::ReportRequest as ProtobufReportRequest, report_grpc};
use mc_fog_recovery_db_iface::{RecoveryDb, ReportData, ReportDb};
use mc_fog_report_server::{Materials, Server};
use mc_fog_sql_recovery_db::test_utils::SqlRecoveryDbTestContext;
use mc_fog_test_infra::db_tests::random_kex_rng_pubkey;
use mc_util_from_random::FromRandom;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use mc_util_uri::FogUri;
use rand::{rngs::StdRng, SeedableRng};
use std::{str::FromStr, sync::Arc};

#[test_with_logger]
fn report_server_grpc_tests(logger: Logger) {
    let mut rng: StdRng = SeedableRng::from_seed([123u8; 32]);
    let db_test_context = SqlRecoveryDbTestContext::new(logger.clone());

    let db = db_test_context.get_db_instance();
    let ingress_key = CompressedRistrettoPublic::from(&RistrettoPublic::from_random(&mut rng));
    db.new_ingress_key(&ingress_key, 1).unwrap();

    let (pem_chain, signing_keypair) = mc_crypto_x509_test_vectors::ok_rsa_chain_25519_leaf();
    let materials = Materials::from_pem_keypair(pem_chain, signing_keypair)
        .expect("Could not parse x509 test vectors key");

    let client_uri = FogUri::from_str("insecure-fog://0.0.0.0:3400").unwrap();
    let mut server = Server::new(db, &client_uri, materials, logger.clone());
    server.start();

    let env = Arc::new(grpcio::EnvBuilder::new().build());

    let report_client = {
        let ch = ChannelBuilder::default_channel_builder(env.clone())
            .connect_to_uri(&client_uri, &logger);
        report_grpc::ReportApiClient::new(ch)
    };

    // Request reports
    let req = ProtobufReportRequest::new();
    let resp = report_client.get_reports(&req).unwrap();

    assert_eq!(resp.reports.len(), 0);

    // Insert a report to the database.
    let db = db_test_context.get_db_instance();

    let invoc_id1 = db
        .new_ingest_invocation(None, &ingress_key, &random_kex_rng_pubkey(&mut rng), 123)
        .unwrap();

    let verification_report0 = VerificationReport {
        sig: Default::default(),
        chain: vec![b"asdf".to_vec(), b"jkl;".to_vec()],
        http_body: "body".to_string(),
    };
    let verification_report1 = VerificationReport {
        sig: Default::default(),
        chain: vec![b"jkl;".to_vec(), b"asdf".to_vec()],
        http_body: "different body".to_string(),
    };

    let report1 = ReportData {
        ingest_invocation_id: Some(invoc_id1),
        report: verification_report0.clone(),
        pubkey_expiry: 102030,
    };
    let report_id1 = "";
    // insert vr0 as (nil)
    db.set_report(&ingress_key, report_id1, &report1).unwrap();

    // Request reports
    let req = ProtobufReportRequest::new();
    let resp = report_client.get_reports(&req).unwrap();

    assert_eq!(resp.reports.len(), 1);
    assert_eq!(
        VerificationReport::from(resp.reports[0].get_report()),
        verification_report0
    );
    assert_eq!(resp.reports[0].get_pubkey_expiry(), report1.pubkey_expiry);

    // Update report
    let updated_report1 = ReportData {
        ingest_invocation_id: Some(invoc_id1),
        report: verification_report1.clone(),
        pubkey_expiry: 424242,
    };

    // insert vr1 as (nil)
    db.set_report(&ingress_key, report_id1, &updated_report1)
        .unwrap();

    // Request reports
    let req = ProtobufReportRequest::new();
    let resp = report_client.get_reports(&req).unwrap();

    assert_eq!(resp.reports.len(), 1);
    assert_eq!(
        VerificationReport::from(resp.reports[0].get_report()),
        verification_report1
    );
    assert_eq!(
        resp.reports[0].get_pubkey_expiry(),
        updated_report1.pubkey_expiry
    );

    // Add second report (DB contains report_bytes1 for report_id1)
    let report2 = ReportData {
        ingest_invocation_id: Some(invoc_id1),
        report: verification_report0.clone(),
        pubkey_expiry: 10203040,
    };
    let report_id2 = "report2";
    // insert vr0 as report2
    db.set_report(&ingress_key, report_id2, &report2).unwrap();

    // Request reports
    let req = ProtobufReportRequest::new();
    let resp = report_client.get_reports(&req).unwrap();

    assert_eq!(resp.reports.len(), 2);

    assert_eq!(
        VerificationReport::from(resp.reports[0].get_report()),
        verification_report1
    );
    assert_eq!(
        resp.reports[0].get_pubkey_expiry(),
        updated_report1.pubkey_expiry
    );

    assert_eq!(
        VerificationReport::from(resp.reports[1].get_report()),
        verification_report0
    );
    assert_eq!(resp.reports[1].get_pubkey_expiry(), report2.pubkey_expiry);

    // Remove (nil) report
    db.remove_report(report_id1).unwrap();

    // Request reports
    let req = ProtobufReportRequest::new();
    let resp = report_client.get_reports(&req).unwrap();

    assert_eq!(resp.reports.len(), 1);
    assert_eq!(
        VerificationReport::from(resp.reports[0].get_report()),
        verification_report0
    );
    assert_eq!(resp.reports[0].get_pubkey_expiry(), report2.pubkey_expiry);
}
