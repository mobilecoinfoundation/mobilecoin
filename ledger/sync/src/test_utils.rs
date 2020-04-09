// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::{TransactionFetcherError, TransactionsFetcher};
use common::ResponderId;
use ledger_db::Ledger;
use transaction::{Block, RedactedTx};

impl TransactionFetcherError for String {}

#[derive(Clone)]
pub struct MockTransactionsFetcher<L: Ledger + Sync> {
    pub ledger: L,
}

impl<L: Ledger + Sync> MockTransactionsFetcher<L> {
    pub fn new(ledger: L) -> Self {
        Self { ledger }
    }
}

impl<L: Ledger + Sync> TransactionsFetcher for MockTransactionsFetcher<L> {
    type Error = String;

    fn get_transactions_by_block(
        &self,
        _safe_responder_ids: &[ResponderId],
        block: &Block,
    ) -> Result<Vec<RedactedTx>, Self::Error> {
        self.ledger
            .get_transactions_by_block(block.index)
            .map_err(|e| {
                format!(
                    "Error getting transactions for block #{}: {:?}",
                    block.index, e
                )
            })
    }
}
