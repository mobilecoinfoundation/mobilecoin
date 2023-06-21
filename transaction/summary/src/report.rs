// Copyright (c) 2018-2023 The MobileCoin Foundation

//! A TxSummaryUnblindingReport, containing the set of verified information
//! about a transaction.

use core::fmt::Display;

use displaydoc::Display;
use heapless::Vec;

use mc_core::account::ShortAddressHash;
use mc_transaction_types::{
    constants::{MAX_INPUTS, MAX_OUTPUTS},
    Amount, TokenId,
};

use super::Error;

/// An entity with whom a transaction can interact, and who can be identified
/// by the TxSummary verification process
#[derive(Clone, Debug, Display, Eq, Ord, PartialEq, PartialOrd)]
pub enum TransactionEntity {
    /// Outputs to a non-change address that we control (hash {0})
    OurAddress(ShortAddressHash),

    /// Outputs to other accounts (hash {0})
    OtherAddress(ShortAddressHash),

    /// Swap counterparty
    Swap,
}

/// Generic transaction report interface
// (There is at this time only one report implementation, however, this trait
// is particularly useful for eliding generics when using this and is expected
// to be helpful when building support for account info caching.)
pub trait TransactionReport {
    /// Add value to the running transaction totals
    fn input_add(&mut self, amount: Amount) -> Result<(), Error>;

    /// Subtract an amount from the transaction total, used for change outputs
    /// and SCIs if enabled
    fn change_sub(&mut self, amount: Amount) -> Result<(), Error>;

    /// Add SCI input not owned by our account
    fn sci_add(&mut self, _amount: Amount) -> Result<(), Error>;

    /// Add output value for a particular entity / address to the report
    fn output_add(&mut self, entity: TransactionEntity, amount: Amount) -> Result<(), Error>;

    /// Set the network fee
    fn network_fee_set(&mut self, amount: Amount) -> Result<(), Error>;

    /// Set the tombstone block
    fn tombstone_block_set(&mut self, value: u64) -> Result<(), Error>;

    /// Finalise the report, checking balances and sorting report entries
    fn finalize(&mut self) -> Result<(), Error>;
}

/// [TransactionReport] impl for `&mut T` where `T: TransactionReport`
impl<T: TransactionReport> TransactionReport for &mut T {
    fn input_add(&mut self, amount: Amount) -> Result<(), Error> {
        <T as TransactionReport>::input_add(self, amount)
    }

    fn change_sub(&mut self, amount: Amount) -> Result<(), Error> {
        <T as TransactionReport>::change_sub(self, amount)
    }

    fn sci_add(&mut self, amount: Amount) -> Result<(), Error> {
        <T as TransactionReport>::sci_add(self, amount)
    }

    fn output_add(&mut self, entity: TransactionEntity, amount: Amount) -> Result<(), Error> {
        <T as TransactionReport>::output_add(self, entity, amount)
    }

    fn network_fee_set(&mut self, amount: Amount) -> Result<(), Error> {
        <T as TransactionReport>::network_fee_set(self, amount)
    }

    fn tombstone_block_set(&mut self, value: u64) -> Result<(), Error> {
        <T as TransactionReport>::tombstone_block_set(self, value)
    }

    fn finalize(&mut self) -> Result<(), Error> {
        <T as TransactionReport>::finalize(self)
    }
}

/// Compute maximum number of outputs and inputs to be supported by a report
pub const MAX_RECORDS: usize = MAX_OUTPUTS as usize + MAX_INPUTS as usize;

/// Maximum number of currencies with totals supported in a single report.
///
/// It is expected that _most_ transactions will contain one total, however,
/// this should be large enough to support SCIs with other token types
pub const MAX_TOTALS: usize = 4;

/// A report of the parties and balance changes due to a transaction,
/// produced for a given TxSummary and TxSummaryUnblindingData.
///
/// This uses a double-entry approach where outputs and totals should be
/// balanced. For each token, totals = our inputs - sum(change outputs) ==
/// sum(other outputs) + fee
///
/// SCI inputs are currently ignored
#[derive(Clone, Debug, Default)]
pub struct TxSummaryUnblindingReport<
    const RECORDS: usize = MAX_RECORDS,
    const TOTALS: usize = MAX_TOTALS,
> {
    /// Transaction outputs aggregated by address and token type
    pub outputs: Vec<(TransactionEntity, TokenId, u64), RECORDS>,

    /// Total balance change for our account for each type of token in the
    /// transaction.
    ///
    /// totals = our inputs - sum(change outputs)
    ///
    /// Note that swap inputs are elided as these are not inputs
    /// owned by us (ie. are not spent from our account)
    pub totals: Vec<(TokenId, TotalKind, i64), TOTALS>,

    /// The network fee that we pay to execute the transaction
    pub network_fee: Amount,

    /// The tombstone block associated to this transaction
    pub tombstone_block: u64,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum TotalKind {
    /// Input owned by our account
    Ours,
    /// Input owned by SCI counterparty
    Sci,
}

impl<const RECORDS: usize, const TOTALS: usize> TransactionReport
    for TxSummaryUnblindingReport<RECORDS, TOTALS>
{
    /// Add owned input, added to the transaction total
    fn input_add(&mut self, amount: Amount) -> Result<(), Error> {
        let Amount { token_id, value } = amount;

        // Ensure value will not overflow
        let value = i64::try_from(value).map_err(|_| Error::NumericOverflow)?;

        // Check for existing total entry for this token
        match self
            .totals
            .iter_mut()
            .find(|(t, k, _)| t == &token_id && *k == TotalKind::Ours)
        {
            // If we have an entry, add the value to this
            Some(v) => v.2 = v.2.checked_add(value).ok_or(Error::NumericOverflow)?,
            // If we do not, create a new entry
            None => self
                .totals
                .push((token_id, TotalKind::Ours, value))
                .map_err(|_| Error::BufferOverflow)?,
        }

        Ok(())
    }

    /// Add change output, subtracted from the transaction total
    fn change_sub(&mut self, amount: Amount) -> Result<(), Error> {
        let Amount { token_id, value } = amount;

        // Ensure value will not overflow
        let value = i64::try_from(value).map_err(|_| Error::NumericOverflow)?;

        // Check for existing total entry for this token
        match self
            .totals
            .iter_mut()
            .find(|(t, k, _)| t == &token_id && *k == TotalKind::Ours)
        {
            // If we have an entry, subtract the change value from this
            Some(v) => v.2 = v.2.checked_sub(value).ok_or(Error::NumericOverflow)?,
            // If we do not, create a new entry
            None => self
                .totals
                .push((token_id, TotalKind::Ours, -value))
                .map_err(|_| Error::BufferOverflow)?,
        }

        Ok(())
    }

    /// Add SCI (or other) input not owned by our account
    fn sci_add(&mut self, amount: Amount) -> Result<(), Error> {
        let Amount { token_id, value } = amount;

        // Ensure value will not overflow
        let value = i64::try_from(value).map_err(|_| Error::NumericOverflow)?;

        // Check for existing total entry for this token
        match self
            .totals
            .iter_mut()
            .find(|(t, k, _)| t == &token_id && *k == TotalKind::Sci)
        {
            // If we have an entry, add the value to this
            Some(v) => v.2 = v.2.checked_add(value).ok_or(Error::NumericOverflow)?,
            // If we do not, create a new entry
            None => self
                .totals
                .push((token_id, TotalKind::Sci, value))
                .map_err(|_| Error::BufferOverflow)?,
        }
        Ok(())
    }

    /// Add output value to a particular entity / address to the report
    fn output_add(&mut self, entity: TransactionEntity, amount: Amount) -> Result<(), Error> {
        let Amount { token_id, value } = amount;

        // Check for existing output for this address
        match self
            .outputs
            .iter_mut()
            .find(|(e, t, _)| t == &token_id && e == &entity)
        {
            // If we have an entry, subtract the change value from this
            Some((_, _, v)) => *v = v.checked_add(value).ok_or(Error::NumericOverflow)?,
            // If we do not, create a new entry
            None => self
                .outputs
                .push((entity, token_id, value))
                .map_err(|_| Error::BufferOverflow)?,
        }

        Ok(())
    }

    /// Add network fee to the report
    fn network_fee_set(&mut self, amount: Amount) -> Result<(), Error> {
        // Set fee value
        self.network_fee = amount;

        Ok(())
    }

    /// Set tombstone block in the report
    fn tombstone_block_set(&mut self, value: u64) -> Result<(), Error> {
        self.tombstone_block = value;
        Ok(())
    }

    /// Finalise report, checking and balancing totals and sorting report
    /// entries
    fn finalize(&mut self) -> Result<(), Error> {
        // Sort outputs and totals
        self.sort();

        // For each token id, check that inputs match outputs
        // (this is only executed where _totals_ exist, so skipped
        // for the current SCI implementation)
        for (token_id, total_kind, value) in &mut self.totals {
            // Sum outputs for this token id
            let mut balance = 0u64;
            for (e, id, v) in &self.outputs {
                // Skip other tokens
                if id != token_id {
                    continue;
                }

                // Handle balance / values depending on whether the total is from us or a swap
                // counterparty
                match total_kind {
                    // If it's coming from our account, track total balance
                    TotalKind::Ours => {
                        balance = balance.checked_add(*v).ok_or(Error::NumericOverflow)?;
                    }
                    // If it's coming from an SCI, and returned to the counterparty, reduce total by
                    // outgoing value
                    TotalKind::Sci if e == &TransactionEntity::Swap => {
                        *value = value.checked_sub(*v as i64).ok_or(Error::NumericOverflow)?;
                    }
                    // If it's coming from an SCI to us, add to total balance
                    TotalKind::Sci if e != &TransactionEntity::Swap => {
                        balance = balance.checked_add(*v).ok_or(Error::NumericOverflow)?;
                    }
                    _ => (),
                }
            }

            // Add network fee for matching token id
            if &self.network_fee.token_id == token_id {
                balance = balance
                    .checked_add(self.network_fee.value)
                    .ok_or(Error::NumericOverflow)?;
            }

            // Check that the balance matches the total
            if balance != *value as u64 {
                return Err(Error::AmountVerificationFailed);
            }
        }

        Ok(())
    }
}

impl<const RECORDS: usize, const TOTALS: usize> TxSummaryUnblindingReport<RECORDS, TOTALS> {
    /// Create a new report instance
    pub fn new() -> Self {
        Self {
            outputs: Vec::new(),
            totals: Vec::new(),
            network_fee: Default::default(),
            tombstone_block: 0,
        }
    }

    /// Sort balance changes and totals
    ///
    /// This should be called prior to displaying the report.
    pub fn sort(&mut self) {
        // TODO: should we remove zeroed balances / totals?

        self.outputs[..].sort_by_key(|(_, t, _)| *t);
        self.outputs[..].sort_by_key(|(e, _, _)| e.clone());

        self.totals[..].sort_by_key(|(t, _, _)| *t);
        self.totals[..].sort_by_key(|(_, k, _)| *k);
    }
}

// This is a proof-of-concept, it doesn't map token id's to their symbol when
// displaying.
impl<const RECORDS: usize, const TOTALS: usize> Display
    for TxSummaryUnblindingReport<RECORDS, TOTALS>
{
    fn fmt(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        let mut current_entity = None;
        for (entity, tok, val) in self.outputs.iter() {
            if Some(entity) != current_entity.as_ref() {
                writeln!(formatter, "{entity}:")?;
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
    use rand::random;

    use super::*;

    #[test]
    fn test_report_size() {
        assert_eq!(core::mem::size_of::<TxSummaryUnblindingReport>(), 1416);
    }

    #[test]
    fn test_report_totals() {
        let mut report = TxSummaryUnblindingReport::<16>::new();

        let amounts = [
            Amount::new(50, TokenId::from(1)),
            Amount::new(50, TokenId::from(1)),
            Amount::new(100, TokenId::from(2)),
            Amount::new(200, TokenId::from(2)),
        ];

        for a in amounts {
            report.input_add(a).unwrap();
        }

        // Check total inputs
        report.sort();
        assert_eq!(
            &report.totals[..],
            &[
                (TokenId::from(1), TotalKind::Ours, 100),
                (TokenId::from(2), TotalKind::Ours, 300)
            ]
        );

        // Subtract change amounts
        report
            .change_sub(Amount::new(25, TokenId::from(1)))
            .unwrap();
        report
            .change_sub(Amount::new(50, TokenId::from(2)))
            .unwrap();

        // Check total inputs - change
        assert_eq!(
            &report.totals[..],
            &[
                (TokenId::from(1), TotalKind::Ours, 75),
                (TokenId::from(2), TotalKind::Ours, 250)
            ]
        );
    }

    #[test]
    fn test_report_balances() {
        let mut report = TxSummaryUnblindingReport::<16>::new();

        // Setup random addresses, sorted so these match the report entry order
        let mut addrs = [
            TransactionEntity::OtherAddress(ShortAddressHash::from(random::<[u8; 16]>())),
            TransactionEntity::OtherAddress(ShortAddressHash::from(random::<[u8; 16]>())),
        ];
        addrs.sort();

        let amounts = [
            (addrs[0].clone(), Amount::new(50, TokenId::from(1))),
            (addrs[0].clone(), Amount::new(50, TokenId::from(1))),
            (addrs[0].clone(), Amount::new(80, TokenId::from(2))),
            (addrs[1].clone(), Amount::new(120, TokenId::from(2))),
            (TransactionEntity::Swap, Amount::new(200, TokenId::from(2))),
        ];

        for (e, a) in amounts {
            report.output_add(e, a).unwrap();
        }

        // Check total outputs
        report.sort();
        assert_eq!(
            &report.outputs[..],
            &[
                (addrs[0].clone(), TokenId::from(1), 100),
                (addrs[0].clone(), TokenId::from(2), 80),
                (addrs[1].clone(), TokenId::from(2), 120),
                (TransactionEntity::Swap, TokenId::from(2), 200),
            ]
        );
    }
}
