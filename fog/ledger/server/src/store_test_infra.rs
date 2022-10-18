//! Testing infrastructure for tests on the "store" portion of the 
//! ledger/store system.

use mc_account_keys::PublicAddress;
use mc_common::logger::Logger;
#[allow(unused_imports)]
use mc_fog_test_infra::{mock_client::PassThroughViewClient, mock_users::{UserData, UserPool, make_random_tx}, get_enclave_path};
use mc_util_test_helper::Rng;
use rand::rngs::OsRng;
use tempdir::TempDir;
#[allow(unused_imports)]
use std::env::temp_dir;
use std::path::PathBuf;

pub fn generate_testing_ledger(test_name: &'static str, _logger: Logger) -> Vec<PublicAddress> { 
    const NUM_ACCOUNTS: usize = 32; 

    // Set up our directories. 
    let test_dir_name = format!("fog_ledger_test_{}", test_name);
    let tempdir = TempDir::new(&test_dir_name).expect("Could not produce test_ledger tempdir");
    let test_path = PathBuf::from(tempdir.path());
    let user_keys_path = test_path.join(PathBuf::from("keys/")); 
    if !user_keys_path.exists() { 
        std::fs::create_dir(&user_keys_path).unwrap();
    }
    
    // Construct a certificate to act as the fog authority for testing. 
    let der_bytes = pem::parse(mc_crypto_x509_test_vectors::ok_rsa_head())
        .expect("Could not parse DER bytes from PEM certificate file")
        .contents;
    let fog_authority_spki = x509_signature::parse_certificate(&der_bytes)
        .expect("Could not parse X509 certificate from DER bytes")
        .subject_public_key_info()
        .spki();

    // Misc
    let fog_report_url = "fog://fog.unittest.com";
    let fog_report_id = format!("fog_test_report_{}", test_name);

    // Seed for prng.
    let mut seed: [u8; 32] = [0;32]; 
    let mut rng = OsRng::default(); 
    rng.try_fill(&mut seed).unwrap(); 

    mc_util_keyfile::keygen::write_default_keyfiles(
        &user_keys_path,
        NUM_ACCOUNTS,
        Some(&fog_report_url),
        &fog_report_id,
        Some(&fog_authority_spki),
        seed,
    )
    .unwrap();
    
    // Read public keys for a selection of test "users" from disk
    // Possibly write_default_keyfiles and then read_default_pubfiles in sequence? 
    let pub_addrs = mc_util_keyfile::keygen::read_default_pubfiles(user_keys_path)
        .expect("Could not read public key files");
    
    assert_ne!(0, pub_addrs.len());

    pub_addrs
}