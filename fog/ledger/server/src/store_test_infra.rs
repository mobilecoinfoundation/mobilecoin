//! Testing infrastructure for tests on the "store" portion of the 
//! ledger/store system.

use mc_common::logger::Logger;
#[allow(unused_imports)]
use mc_fog_test_infra::{mock_client::PassThroughViewClient, mock_users::{UserData, UserPool, make_random_tx}, get_enclave_path};
#[allow(unused_imports)]
use std::env::temp_dir;
use std::path::PathBuf;

const TEST_LEDGER_PARENT_DIR: &'static str = "mc_fog_tests/";

pub fn generate_testing_ledger(test_name: &'static str, key_dir: PathBuf, _logger: Logger) { 
    let parent_dir = temp_dir().join(PathBuf::from(TEST_LEDGER_PARENT_DIR));
    let _test_dir = parent_dir.join(PathBuf::from(test_name));
    
    // Read public keys for a selection of test "users" from disk
    let pub_addrs = mc_util_keyfile::keygen::read_default_pubfiles(key_dir)
        .expect("Could not read public key files");
    assert_ne!(0, pub_addrs.len());
}