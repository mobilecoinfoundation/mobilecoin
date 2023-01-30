// Copyright (c) 2018-2022 The MobileCoin Foundation

//! A TxSummaryUnblindingReport, containing the set of verified information
//! about a transaction.

use super::Error;
use core::fmt::Display;
use displaydoc::Display;

use core::writeln;

use mc_core::account::ShortAddressHash;
use mc_transaction_types::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    amount::Amount, TokenId,
};
use mc_util_vec_map::VecMap;

/// An entity with whom a transaction can interact, and who can be identified
/// by the TxSummary verification process
#[derive(Clone, Debug, Display, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransactionEntity {
    /// Self
    Ourself,
    /// Address hash {0}
    Address(ShortAddressHash),
    /// Swap counterparty
    Swap,
}

pub const MAX_RECORDS: usize = MAX_OUTPUTS as usize + MAX_INPUTS as usize;

/// A report of the parties and balance changes due to a transaction.
/// This can be produced for a given TxSummary and TxSummaryUnblindingData.
#[derive(Clone, Debug, Default)]
pub struct TxSummaryUnblindingReport<const RECORDS: usize = MAX_RECORDS> {
    /// The set of balance changes that we have observed
    // Note: We can save about 210 bytes on the stack if we store TokenId as
    // a [u8; 8] to avoid alignment requirements. TBD if that's worth it.
    pub balance_changes: VecMap<(TransactionEntity, TokenId), i64, RECORDS>,
    /// The network fee that we pay
    pub network_fee: Amount,
    /// The tombstone block associated to this transaction
    pub tombstone_block: u64,
}

impl <const RECORDS: usize> TxSummaryUnblindingReport<RECORDS> {
    /// Add value to the balance report, for some entity
    pub fn balance_add(
        &mut self,
        entity: TransactionEntity,
        token_id: TokenId,
        value: u64,
    ) -> Result<(), Error> {
        let value = i64::try_from(value).map_err(|_| Error::NumericOverflow)?;
        let stored = self
            .balance_changes
            .get_mut_or_insert_with(&(entity, token_id), || 0)
            .map_err(|_| Error::BufferOverflow)?;
        *stored = stored.checked_add(value).ok_or(Error::NumericOverflow)?;
        Ok(())
    }

    /// Subtract value from the balance report, for some entity
    pub fn balance_subtract(
        &mut self,
        entity: TransactionEntity,
        token_id: TokenId,
        value: u64,
    ) -> Result<(), Error> {
        let value = i64::try_from(value).map_err(|_| Error::NumericOverflow)?;
        let stored = self
            .balance_changes
            .get_mut_or_insert_with(&(entity, token_id), || 0)
            .map_err(|_| Error::BufferOverflow)?;
        *stored = stored.checked_sub(value).ok_or(Error::NumericOverflow)?;
        Ok(())
    }

    /// This should be done before displaying the report
    pub fn sort(&mut self) {
        self.balance_changes.sort();
    }
}

// This is a proof-of-concept, it doesn't map token id's to their symbol when
// displaying.
impl <const RECORDS: usize> core::fmt::Display for TxSummaryUnblindingReport<RECORDS> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut current_entity = None;
        for ((entity, tok), val) in self.balance_changes.iter() {
            if Some(entity) != current_entity.as_ref() {
                writeln!(formatter, "{}:", entity)?;
                current_entity = Some(entity.clone());
            }
            writeln!(formatter, "\t{}: {}", *tok, val)?;
        }
        writeln!(
            formatter,
            "Network fee: {}: {}",
            *self.network_fee.token_id, self.network_fee.value
        )?;
        writeln!(formatter, "Tombstone block: {}", self.tombstone_block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_report_size_size() {
        assert_eq!(core::mem::size_of::<TxSummaryUnblindingReport>(), 1320);
    }
}
