// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Test Client

use mc_common::logger::{create_app_logger, o};

use mc_fog_test_client::{config::Config, error::TestClientError, test_client::TestClient};

use structopt::StructOpt;

fn main() {
    mc_common::setup_panic_handler();
    let (logger, _global_logger_guard) = create_app_logger(o!());

    let config = Config::from_args();

    let account_keys = config.load_accounts(&logger);

    match TestClient::new(
        account_keys,
        config.consensus_config.consensus_validators,
        config.fog_ledger,
        config.fog_view,
        logger,
    )
    .consensus_wait(config.consensus_wait)
    .ledger_sync_wait(config.ledger_sync_wait)
    .transactions(config.num_transactions)
    .transfer_amount(config.transfer_amount)
    .run_test()
    {
        Ok(()) => println!("All tests passed"),
        Err(TestClientError::TxTimeout) => panic!(
            "Transactions could not clear in {:?} seconds",
            config.consensus_wait
        ),
        Err(e) => panic!("Unexpected error {:?}", e),
    }
}
