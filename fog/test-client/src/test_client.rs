// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Test Client

use crate::error::TestClientError;

use mc_account_keys::ShortAddressHash;
use mc_common::logger::{log, Logger};
use mc_crypto_rand::McRng;
use mc_fog_sample_paykit::{AccountKey, Client, ClientBuilder, TransactionStatus, Tx};
use mc_transaction_core::{
    constants::{MINIMUM_FEE, RING_SIZE},
    BlockIndex,
};
use mc_transaction_std::MemoType;
use mc_util_uri::ConsensusClientUri;
use more_asserts::assert_gt;
use std::{
    thread,
    time::{Duration, Instant, SystemTime},
};

pub struct TestClient {
    consensus_wait: Duration,
    ledger_sync_wait: Duration,
    transactions: usize,
    transfer_amount: u64,
    account_keys: Vec<AccountKey>,
    consensus_uris: Vec<ConsensusClientUri>,
    fog_ledger: String,
    fog_view: String,
    retry_attempts: u32,
    logger: Logger,
}

impl TestClient {
    pub fn new(
        account_keys: Vec<AccountKey>,
        consensus_uris: Vec<ConsensusClientUri>,
        fog_ledger: String,
        fog_view: String,
        logger: Logger,
    ) -> Self {
        Self {
            consensus_wait: Duration::from_secs(10),
            ledger_sync_wait: Duration::from_secs(10),
            transactions: 10,
            transfer_amount: std::u64::MAX,
            account_keys,
            consensus_uris,
            fog_ledger,
            fog_view,
            retry_attempts: 100,
            logger,
        }
    }

    pub fn consensus_wait(&mut self, val: Duration) -> &mut Self {
        self.consensus_wait = val;
        self
    }

    pub fn ledger_sync_wait(&mut self, val: Duration) -> &mut Self {
        self.ledger_sync_wait = val;
        self
    }

    pub fn transactions(&mut self, val: usize) -> &mut Self {
        self.transactions = val;
        self
    }

    pub fn transfer_amount(&mut self, val: u64) -> &mut Self {
        self.transfer_amount = val;
        self
    }

    pub fn build_clients(&self, client_count: usize) -> Vec<Client> {
        let mut clients = Vec::new();
        // Need at least 2 clients to send transactions to each other.
        assert_gt!(client_count, 1);

        // Build an address book for each client
        let address_book: Vec<_> = self
            .account_keys
            .iter()
            .map(|x| x.default_subaddress())
            .collect();

        for (i, account_key) in self.account_keys.iter().enumerate() {
            log::debug!(
                self.logger,
                "Now building client for account_key {} {:?}",
                i,
                account_key
            );
            let uri = &self.consensus_uris[i % self.consensus_uris.len()];
            let client = ClientBuilder::new(
                uri.clone(),
                self.fog_view.clone(),
                self.fog_ledger.clone(),
                account_key.clone(),
                self.logger.clone(),
            )
            .ring_size(RING_SIZE)
            .address_book(address_book.clone())
            .build();
            clients.push(client);
        }
        clients
    }

    pub fn transfer(
        &self,
        source_client: &mut Client,
        target_client: &mut Client,
    ) -> Result<Tx, TestClientError> {
        let target_address = target_client.get_account_key().default_subaddress();
        // Override report url
        log::debug!(
            self.logger,
            "Attempting to transfer {} ({})",
            self.transfer_amount,
            source_client.consensus_service_address()
        );

        // First do a balance check to flush out any spent txos
        source_client.check_balance()?;

        let mut rng = McRng::default();
        assert!(target_address.fog_report_url().is_some());

        // Get the current fee from consensus
        let fee = source_client.get_fee().unwrap_or(MINIMUM_FEE);

        let transaction = source_client.build_transaction(
            self.transfer_amount,
            &target_address,
            &mut rng,
            fee,
        )?;
        source_client.send_transaction(&transaction)?;
        Ok(transaction)
    }

    /// Waits for a transaction to be accepted by the network
    ///
    /// Uses the client to poll a fog service until the submitted transaction
    /// either appears or has expired. Panics if the transaction is not
    /// accepted.
    ///
    /// Arguments:
    /// * client: The client to use for this check
    /// * transaction: The (submitted) transaction to check if it landed
    ///
    /// Returns:
    /// * A block index in which the transaction landed, or a test client error.
    pub fn ensure_transaction_is_accepted(
        &self,
        client: &mut Client,
        transaction: &Tx,
    ) -> Result<BlockIndex, TestClientError> {
        // Wait until ledger server can see all of these key images
        let deadline = Instant::now() + self.consensus_wait;
        let retry_wait = self.consensus_wait / self.retry_attempts;
        let mut counter = 0usize;
        loop {
            match client.is_transaction_present(&transaction)? {
                TransactionStatus::Appeared(block_index) => return Ok(block_index),
                TransactionStatus::Expired => panic!("Transaction was not accepted!"),
                TransactionStatus::Unknown => {}
            }
            if Instant::now() > deadline {
                return Err(TestClientError::SubmittedTxTimeout);
            }
            counter += 1;
            log::info!(
                self.logger,
                "Retry {}/{}: Checking transaction again after {:?}...",
                counter,
                self.retry_attempts,
                retry_wait
            );
            thread::sleep(retry_wait);
        }
    }

    /// Ensure that after all fog servers have caught up and the client has data
    /// up to a certain number of blocks, the client computes the expected
    /// balance.
    ///
    /// Arguments:
    /// * block_index: The block_index containing new transactions that must be
    ///   in the balance
    /// * expected_balance: The expected balance to compute after this
    ///   block_index is included
    pub fn ensure_expected_balance_after_block(
        &self,
        client: &mut Client,
        block_index: BlockIndex,
        expected_balance: u64,
    ) -> Result<(), TestClientError> {
        let start = Instant::now();
        let retry_wait = self.consensus_wait / self.retry_attempts;
        for i in 0..self.retry_attempts {
            let (new_balance, new_block_count) = client.check_balance()?;

            // Wait for client cursor to include the index where the transaction landed.
            if u64::from(new_block_count) > block_index {
                log::debug!(
                    self.logger,
                    "Txo cursor now {} > block_index {}, after {:?}",
                    new_block_count,
                    block_index,
                    start.elapsed()
                );
                log::debug!(
                    self.logger,
                    "Expected balance: {:?}, and got: {:?}",
                    expected_balance,
                    new_balance
                );
                assert_eq!(expected_balance, new_balance);
                log::info!(self.logger, "Successful transfer");
                return Ok(());
            }
            log::trace!(
                self.logger,
                "Attempt {}/{}: num_blocks = {} but tx expected in block index = {}, retry in {:?}...",
                i + 1,
                self.retry_attempts,
                new_block_count,
                block_index,
                retry_wait
            );
            thread::sleep(retry_wait);
        }
        Err(TestClientError::TxTimeout)
    }

    /// Attempt a double spend on the transaction.
    pub fn attempt_double_spend(
        &self,
        client: &mut Client,
        transaction: &Tx,
    ) -> Result<(), TestClientError> {
        log::info!(self.logger, "Now attempting spent key image test");
        // NOTE: without the wait, the call to send_transaction would succeed.
        //       This test is a little ambiguous because it is testing that
        //       the transaction cannot even be sent, not just that it fails to
        //       pass consensus.
        thread::sleep(self.ledger_sync_wait);
        match client.send_transaction(transaction) {
            Ok(_) => {
                log::error!(
                    self.logger,
                    "Double spend succeeded. Check whether the ledger is up-to-date"
                );
                Err(TestClientError::DoubleSpend)
            }
            Err(e) => {
                log::info!(self.logger, "Double spend failed with {:?}", e);
                Ok(())
            }
        }
    }

    pub fn run_test(&self) -> Result<(), TestClientError> {
        let client_count = self.account_keys.len() as usize;
        log::debug!(self.logger, "Creating {} clients", client_count);
        let mut clients = self.build_clients(client_count);

        log::debug!(self.logger, "Generating and testing transactions");

        let start_time = SystemTime::now();
        for ti in 0..self.transactions as usize {
            log::debug!(self.logger, "Transation: {:?}", ti);
            // Rust doesn't allow multiple mutable borrows to vector contents.
            let split_index = ti % (client_count - 1) + 1;
            let (head, tail) = clients.split_at_mut(split_index);
            let source_client: &mut Client = &mut head[split_index - 1];
            let target_client: &mut Client = &mut tail[0];

            let (src_balance, src_cursor) = source_client.check_balance()?;
            log::info!(
                self.logger,
                "client {} has a balance of {} after {} blocks",
                split_index,
                src_balance,
                src_cursor
            );
            let (tgt_balance, tgt_cursor) = target_client.check_balance()?;
            log::info!(
                self.logger,
                "client {} has a balance of {} after {} blocks",
                split_index + 1,
                tgt_balance,
                tgt_cursor
            );
            assert!(src_balance > 0);
            assert!(tgt_balance > 0);

            let fee = source_client.get_fee().unwrap_or(MINIMUM_FEE);
            let transaction = self.transfer(source_client, target_client)?;

            // Wait for key images to land in ledger server
            let transaction_appeared =
                self.ensure_transaction_is_accepted(source_client, &transaction)?;

            // Wait for tx to land in fog view server
            // This test will be as flakey as the accessibility/fees of consensus
            log::info!(self.logger, "Checking balance for source");
            self.ensure_expected_balance_after_block(
                source_client,
                transaction_appeared,
                src_balance - self.transfer_amount - fee,
            )?;
            log::info!(self.logger, "Checking balance for target");
            self.ensure_expected_balance_after_block(
                target_client,
                transaction_appeared,
                tgt_balance + self.transfer_amount,
            )?;

            // Ensure source client got a destination memo, as expected for recoverable
            // transcation history
            match source_client.get_last_memo() {
                Ok(Some(memo)) => match memo {
                    MemoType::Destination(memo) => {
                        assert_eq!(memo.get_total_outlay(), self.transfer_amount + fee);
                        assert_eq!(memo.get_fee(), fee);
                        assert_eq!(memo.get_num_recipients(), 1);
                        assert_eq!(
                            *memo.get_address_hash(),
                            ShortAddressHash::from(
                                &target_client.get_account_key().default_subaddress()
                            )
                        );
                    }
                    _ => {
                        panic!("unexpected memo type")
                    }
                },
                Ok(None) => {
                    panic!("source client didn't find destination memo");
                }
                Err(err) => {
                    panic!("source client memo error: {}", err);
                }
            }

            // Ensure target client got a sender memo, as expected for recoverable
            // transcation history
            match target_client.get_last_memo() {
                Ok(Some(memo)) => match memo {
                    MemoType::AuthenticatedSender(memo) => {
                        assert_eq!(
                            memo.sender_address_hash(),
                            ShortAddressHash::from(
                                &source_client.get_account_key().default_subaddress()
                            )
                        );
                    }
                    _ => {
                        panic!("unexpected memo type")
                    }
                },
                Ok(None) => {
                    panic!("target client didn't find sender memo");
                }
                Err(err) => {
                    panic!("target client memo error: {}", err);
                }
            }

            // Attempt double spend on the last transaction. This is an expensive test.
            if ti == self.transactions - 1 {
                self.attempt_double_spend(source_client, &transaction)?;
            }
        }
        log::debug!(
            self.logger,
            "{} transactions took {}s",
            self.transactions,
            start_time
                .elapsed()
                .expect("Could not get elapsed time")
                .as_secs()
        );
        Ok(())
    }
}
