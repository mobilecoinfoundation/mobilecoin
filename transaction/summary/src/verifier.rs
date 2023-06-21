// Copyright (c) 2018-2023 The MobileCoin Foundation

//! This module provides support for a "streaming" verifier which consumes an
//! extended-message digest, a TxSummary and a TxSummaryUnblindingData,
//! in a piece-wise fashion, and produces an extended-message-and-tx-summary
//! digest, as well as a verified TxSummaryReport which contains the balance
//! deltas for all parties to the transaction.
//!
//! The streaming verifier itself occupies about 1200 bytes on the stack.
//! To take the largest "step" (verifying an output) requires
//! approximately 300 bytes + Fog url length

use crate::report::TransactionReport;

use super::{Error, TransactionEntity};
use mc_core::account::{PublicSubaddress, RingCtAddress, ShortAddressHash};
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    onetime_keys::{create_shared_secret, create_tx_out_public_key, create_tx_out_target_key},
    CompressedCommitment,
};
use mc_transaction_types::{
    domain_separators::EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG, Amount, AmountError,
    BlockVersion, MaskedAmount, TxInSummary, TxOutSummary, UnmaskedAmount,
};

/// A streaming transaction summary verifier for use in hardware wallets,
/// with a dual purpose.
///
/// * Compute the "extended-message-and-tx-summary" digest in a "streaming" way
///   that does not require sending the entire TxSummary at once. Only one input
///   or output needs to be sent at a time.
/// * Simultaneously, stream the TxSummaryUnblindingData, so e.g. every
///   TxOutSummary sent is paired with a TxOutSummaryUnblindingData. Verify this
///   unblinding data against the summary. Then, store a report of the balance
///   change for this party. Return the TxSummaryUnblindingReport along with the
///   final digest, which is fully-verified to be accurate.
///
/// This streaming interface is provided for use by hardware wallets,
/// most users should use the higher-level [verify_tx_summary]
///
/// The TxSummaryUnblindingReport can be displayed to the hardware wallet user,
/// and then if they approve, Ring MLSAGs can be signed over the digest produced
/// by this verifier, knowing what the significance of signing these is.
///
/// Note: The TxSummaryUnblindingReport makes assumptions about the details
/// of how a TxSummary and its constituents digested. These are currently
/// implementation details of the mc-crypto-digestible scheme.
/// If TxSummary digestible annotations are changed then this object's
/// implementation needs to change also.
pub struct TxSummaryStreamingVerifierCtx {
    // The account view private key of the transaction signer.
    // This is used to identify outputs addressed to ourselves regardless of subaddress
    view_private_key: RistrettoPrivate,

    // The account change address for matching outputs
    change_address: PublicSubaddress,

    // The block version that this transaction is targetting
    block_version: BlockVersion,
    // The merlin transcript which we maintain in order to produce the digest
    // at the end.
    transcript: MerlinTranscript,
    // The total number of outputs expected
    expected_num_outputs: usize,
    // The total number of inputs expected
    expected_num_inputs: usize,
    // The count of outputs we have already seen
    output_count: usize,
    // The count of inputs we have already seen
    input_count: usize,
}

impl TxSummaryStreamingVerifierCtx {
    /// Start a new streaming verifier. This takes a few small arguments from
    /// TxSummary and TxSummaryUnblindingData which are needed before we can
    /// consume outputs and inputs. This also takes the view private key of
    /// the signer, which is used to identify outputs that went to the signer.
    ///
    /// Arguments:
    /// * extended_message_digest of the Tx
    /// * block_version of the outputs of the Tx
    /// * expected_num_outputs of the Tx
    /// * expected_num_inputs of the Tx
    /// * view_private_key of the signer, to identify self-payment outputs
    ///
    /// Returns:
    /// * A properly initialized TxSummaryStreamingVerifier
    pub fn new(
        extended_message_digest: &[u8; 32],
        block_version: BlockVersion,
        expected_num_outputs: usize,
        expected_num_inputs: usize,
        view_private_key: RistrettoPrivate,
        change_address: PublicSubaddress,
    ) -> Self {
        let mut transcript =
            MerlinTranscript::new(EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG.as_bytes());
        extended_message_digest.append_to_transcript(b"extended_message", &mut transcript);

        // Append start of TxSummary object
        transcript.append_agg_header(b"tx_summary", b"TxSummary");
        // Append start of TxSummary.outputs list
        transcript.append_seq_header(b"outputs", expected_num_outputs);

        Self {
            view_private_key,
            block_version,
            transcript,
            expected_num_outputs,
            expected_num_inputs,
            output_count: 0,
            input_count: 0,
            change_address,
        }
    }

    /// Stream the next TxOutSummary and matching unblinding data to the
    /// streaming verifier, which will verify and then digest it.
    pub fn digest_output(
        &mut self,
        tx_out_summary: &TxOutSummary,
        unmasked_amount: &UnmaskedAmount,
        address: Option<(ShortAddressHash, impl RingCtAddress)>,
        tx_private_key: Option<&RistrettoPrivate>,
        mut report: impl TransactionReport,
    ) -> Result<(), Error> {
        if self.output_count >= self.expected_num_outputs {
            return Err(Error::UnexpectedOutput);
        }

        // Now try to verify the recipient. This is either ourselves, or someone else
        // with the listed address, or this is associated to an SCI.

        // If we view-key matched the output, then it belongs to one of our subaddresses
        if let Some(amount) = self.view_key_match(tx_out_summary)? {
            // If we have address information
            if let Some((address_hash, address)) = address.as_ref() {
                // Check whether this is to our change address
                if address.view_public_key() == self.change_address.view_public_key()
                    && address.spend_public_key() == self.change_address.spend_public_key()
                {
                    // If this is to our change address, subtract this from the total inputs
                    report.change_sub(amount)?;
                } else {
                    // Otherwise, add this as an output to ourself
                    report
                        .output_add(TransactionEntity::OurAddress(address_hash.clone()), amount)?;
                }
            } else {
                // TODO: If we _don't_ have address information but it's to our own address...
                // what then? is this even possible??!
                panic!("what's the right thing to do here..?");
            }

        // If we didn't match the output, and we have address information, this
        // belongs to someone else
        } else if let Some((address_hash, address)) = address.as_ref() {
            // Otherwise, this belongs to another address

            let amount = Amount::new(unmasked_amount.value, unmasked_amount.token_id.into());
            // In this case, we are given the address of who is supposed to have received
            // this.
            let tx_private_key = tx_private_key.as_ref().ok_or(Error::MissingTxPrivateKey)?;
            // Let's try to verify that the TxOutSummary is as expected
            let expected =
                Self::expected_tx_out_summary(self.block_version, amount, address, tx_private_key)?;
            if &expected == tx_out_summary {
                // Add as an output to the report
                report.output_add(
                    TransactionEntity::OtherAddress(address_hash.clone()),
                    amount,
                )?;
            } else {
                return Err(Error::AddressVerificationFailed);
            }

        // If we didn't match the output, and we don't have address information,
        // this is an SCI
        } else {
            if !tx_out_summary.associated_to_input_rules {
                return Err(Error::MissingDataRequiredToVerifyTxOutRecipient);
            }

            // First try to verify the amount commitment
            let value = unmasked_amount.value;
            let token_id = unmasked_amount.token_id;
            let blinding_factor = unmasked_amount.blinding;
            let generator = mc_crypto_ring_signature::generators(token_id);
            let expected_commitment =
                CompressedCommitment::new(value, blinding_factor.into(), &generator);
            if &expected_commitment
                != tx_out_summary
                    .masked_amount
                    .as_ref()
                    .ok_or(Error::MissingMaskedAmount)?
                    .commitment()
            {
                return Err(Error::AmountVerificationFailed);
            }

            // Add outputs to swap counterparty to the report
            report.output_add(TransactionEntity::Swap, unmasked_amount.into())?;
        }

        // We've now verified the tx_out_summary and added it to the report.
        // Now we need to add it to the digest
        // (See mc-crypto-digestible sources for details around b"")
        tx_out_summary.append_to_transcript(b"", &mut self.transcript);
        self.output_count += 1;

        // If there should be no more outputs, then we should add the preamble for the
        // inputs to the digest.
        if self.output_count == self.expected_num_outputs {
            self.transcript
                .append_seq_header(b"inputs", self.expected_num_inputs);
        }

        Ok(())
    }

    /// Stream the next TxInSummary and matching unblinding data to the
    /// streaming verifier, which will verify and then digest it.
    pub fn digest_input(
        &mut self,
        tx_in_summary: &TxInSummary,
        tx_in_summary_unblinding_data: &UnmaskedAmount,
        mut report: impl TransactionReport,
    ) -> Result<(), Error> {
        if self.output_count != self.expected_num_outputs {
            return Err(Error::StillExpectingMoreOutputs);
        }
        if self.input_count >= self.expected_num_inputs {
            return Err(Error::UnexpectedInput);
        }

        // First try to verify the amount
        let value = tx_in_summary_unblinding_data.value;
        let token_id = tx_in_summary_unblinding_data.token_id;
        let blinding_factor = tx_in_summary_unblinding_data.blinding;
        let generator = mc_crypto_ring_signature::generators(token_id);
        let expected_commitment =
            CompressedCommitment::new(value, blinding_factor.into(), &generator);
        if expected_commitment != tx_in_summary.pseudo_output_commitment {
            return Err(Error::AmountVerificationFailed);
        }

        // Now understand whose input this is. There are two cases
        if tx_in_summary.input_rules_digest.is_empty() {
            // If we have no input rules digest, then this is a normal input
            // add this to the report total
            report.input_add(tx_in_summary_unblinding_data.into())?;
        } else {
            // If we have input rules this is an SCI input and does not impact
            // our balance, but we _can_ track this if required
            report.sci_add(tx_in_summary_unblinding_data.into())?;
        };

        // We've now verified the tx_in_summary and added it to the report.
        // Now we need to add it to the digest
        // (See mc-crypto-digestible sources for details around b"")
        tx_in_summary.append_to_transcript(b"", &mut self.transcript);
        self.input_count += 1;

        Ok(())
    }

    /// Finalize the streaming verifier, after all outputs and then all inputs
    /// have been streamed. Pass in the remaining small bits of TxSummary.
    ///
    /// Arguments:
    /// * fee (from TxSummary)
    /// * tombstone_block (from TxSummary)
    ///
    /// Returns:
    /// * extended-message-and-tx-summary digest
    /// * TxSummaryUnblindingReport, which details all balance changes for all
    ///   parties to this Tx.
    pub fn finalize(
        mut self,
        fee: Amount,
        tombstone_block: u64,
        digest: &mut [u8; 32],
        mut report: impl TransactionReport,
    ) -> Result<(), Error> {
        report.network_fee_set(fee)?;
        report.tombstone_block_set(tombstone_block)?;

        fee.value.append_to_transcript(b"fee", &mut self.transcript);
        (*fee.token_id).append_to_transcript(b"fee_token_id", &mut self.transcript);
        tombstone_block.append_to_transcript(b"tombstone_block", &mut self.transcript);

        // Append the closer of the TxSummary object
        self.transcript
            .append_agg_closer(b"tx_summary", b"TxSummary");

        // Extract the digest
        self.transcript.extract_digest(digest);

        Ok(())
    }

    // Internal: Check if TxOutSummary matches to our view private key
    //
    // Returns:
    // Ok(Some(amount)) - if view key matching succeeded, and reveals the amount
    // Ok(None) - if view key matching failed but no other errors occurred
    // Err - if some structural issue with the TxOutSummary prevented view key
    // matching attempt
    fn view_key_match(&self, tx_out_summary: &TxOutSummary) -> Result<Option<Amount>, Error> {
        let tx_out_shared_secret = mc_crypto_ring_signature::get_tx_out_shared_secret(
            &self.view_private_key,
            &RistrettoPublic::try_from(&tx_out_summary.public_key)?,
        );

        match tx_out_summary
            .masked_amount
            .as_ref()
            .ok_or(Error::MissingMaskedAmount)?
            .get_value(&tx_out_shared_secret)
        {
            Ok((amount, _scalar)) => Ok(Some(amount)),
            Err(AmountError::InconsistentCommitment) => Ok(None),
            Err(err) => Err(Error::Amount(err)),
        }
    }

    // Internal: Compute the expected TxOutSummary for a given set of data.
    // This is a piece of the implementation of TxOut::new.
    //
    // Returns:
    // Ok(TxOutSummary) with the produced TxOutSummary
    // Err if some error prevented construction
    fn expected_tx_out_summary(
        block_version: BlockVersion,
        amount: Amount,
        recipient: &impl RingCtAddress,
        tx_private_key: &RistrettoPrivate,
    ) -> Result<TxOutSummary, Error> {
        let target_key = create_tx_out_target_key(tx_private_key, recipient).into();
        let public_key =
            create_tx_out_public_key(tx_private_key, recipient.spend_public_key().as_ref());

        let shared_secret =
            create_shared_secret(recipient.view_public_key().as_ref(), tx_private_key);

        let masked_amount = Some(MaskedAmount::new(block_version, amount, &shared_secret)?);

        Ok(TxOutSummary {
            target_key,
            public_key: public_key.into(),
            masked_amount,
            associated_to_input_rules: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use alloc::{vec, vec::Vec};

    use rand::rngs::OsRng;

    use crate::{report::TotalKind, TxSummaryUnblindingReport};
    use mc_account_keys::AccountKey;
    use mc_transaction_core::{tx::TxOut, BlockVersion};
    use mc_transaction_types::TokenId;
    use mc_util_from_random::FromRandom;

    // Test the size of the streaming verifier on the stack. This is using heapless.
    #[test]
    fn test_streaming_verifier_size() {
        let s = core::mem::size_of::<TxSummaryStreamingVerifierCtx>();
        assert!(
            s < 1024,
            "TxSummaryStreamingVerifierCtx exceeds size thresold {}/{}",
            s,
            1024
        );
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TxOutReportTest {
        /// Inputs spent in the transaction
        inputs: Vec<(InputType, Amount)>,
        /// Outputs produced by the transaction
        outputs: Vec<(OutputTarget, Amount)>,
        /// Totals / balances by token
        totals: Vec<(TokenId, TotalKind, i64)>,
        /// Changes produced by the transaction
        changes: Vec<(TransactionEntity, TokenId, u64)>,
    }

    #[derive(Clone, Debug, PartialEq)]
    #[allow(dead_code)]
    enum InputType {
        /// An input we own, reducing our balance
        Owned,
        /// A SCI / SWAP input from another account
        Sci,
    }

    #[derive(Clone, Debug, PartialEq)]
    #[allow(dead_code)]
    enum OutputTarget {
        /// An output to ourself (_not_ a change address)
        Ourself,
        /// An output to our change address
        Change,
        /// An output to a third party
        Other,
        /// A swap output (not used in existing reports)
        Swap,
    }

    #[test]
    fn test_report_outputs() {
        let mut rng = OsRng {};

        // Setup accounts for test report
        let sender = AccountKey::random(&mut rng);
        let receiver = AccountKey::random(&mut rng);
        let swap = AccountKey::random(&mut rng);

        let sender_subaddress = sender.default_subaddress();
        let change_subaddress = sender.change_subaddress();
        let target_subaddress = receiver.default_subaddress();
        let swap_subaddress = swap.default_subaddress();

        // Set common token id / amounts for later use
        let token_id = TokenId::from(9);
        let amount = Amount::new(103_000, token_id);
        let fee = 4000;

        // Setup tests
        let tests = &[
            // Output to ourself, should show output to our address and total of output + fee
            TxOutReportTest {
                inputs: vec![(InputType::Owned, Amount::new(amount.value + fee, token_id))],
                outputs: vec![(OutputTarget::Ourself, amount.clone())],
                changes: vec![(
                    TransactionEntity::OurAddress(ShortAddressHash::from(&sender_subaddress)),
                    token_id,
                    amount.value,
                )],
                totals: vec![(token_id, TotalKind::Ours, (amount.value + fee) as i64)],
            },
            // Output to our change address, should show no outputs with balance change = fee
            TxOutReportTest {
                inputs: vec![
                    (
                        InputType::Owned,
                        Amount::new(amount.value / 2 + fee, token_id),
                    ),
                    (InputType::Owned, Amount::new(amount.value / 2, token_id)),
                ],
                outputs: vec![(OutputTarget::Change, amount.clone())],
                changes: vec![
                    //(TransactionEntity::Total, token_id, 0),
                ],
                totals: vec![(token_id, TotalKind::Ours, fee as i64)],
            },
            // Output to someone else, should show their address and total of output + fee
            TxOutReportTest {
                inputs: vec![(InputType::Owned, Amount::new(amount.value + fee, token_id))],
                outputs: vec![(OutputTarget::Other, amount.clone())],
                changes: vec![(
                    TransactionEntity::OtherAddress(ShortAddressHash::from(&target_subaddress)),
                    token_id,
                    amount.value,
                )],
                totals: vec![(token_id, TotalKind::Ours, (amount.value + fee) as i64)],
            },
            // Basic SCI. consuming entire swap, inputs should not count towards totals
            TxOutReportTest {
                inputs: vec![
                    // Our input, sent to SCI
                    (InputType::Owned, Amount::new(10_000 + fee, token_id)),
                    // SCI input, sent to us
                    (InputType::Sci, Amount::new(200, TokenId::from(2))),
                ],
                outputs: vec![
                    // We send the converted token to ourself
                    (OutputTarget::Ourself, Amount::new(200, TokenId::from(2))),
                    // While fulfilling the requirements of the SCI
                    (OutputTarget::Swap, Amount::new(10_000, token_id)),
                ],
                changes: vec![
                    (
                        TransactionEntity::OurAddress(ShortAddressHash::from(&sender_subaddress)),
                        TokenId::from(2),
                        200,
                    ),
                    (TransactionEntity::Swap, token_id, 10_000),
                ],
                totals: vec![
                    // The total is the change to _our_ balance spent during the transaction
                    (token_id, TotalKind::Ours, (10_000 + fee) as i64),
                    // And the SCI input
                    (TokenId::from(2), TotalKind::Sci, (200) as i64),
                ],
            },
            // Partial SCI
            TxOutReportTest {
                inputs: vec![
                    // Our input, owned by us
                    (InputType::Owned, Amount::new(7_500 + fee, token_id)),
                    // SCI input, owned by counterparty
                    (InputType::Sci, Amount::new(200, TokenId::from(2))),
                ],
                outputs: vec![
                    // We send part of the converted token to ourself
                    (OutputTarget::Ourself, Amount::new(150, TokenId::from(2))),
                    // Returning the remaining portion to the swap counterparty
                    (OutputTarget::Swap, Amount::new(50, TokenId::from(2))),
                    // While fulfilling the requirements of the SCI
                    (OutputTarget::Swap, Amount::new(7_500, token_id)),
                ],
                changes: vec![
                    (
                        TransactionEntity::OurAddress(ShortAddressHash::from(&sender_subaddress)),
                        TokenId::from(2),
                        150,
                    ),
                    (TransactionEntity::Swap, TokenId::from(2), 50),
                    (TransactionEntity::Swap, token_id, 7_500),
                ],
                totals: vec![
                    // The total is the change to _our_ balance spent during the transaction
                    (token_id, TotalKind::Ours, (7_500 + fee) as i64),
                    // And the SCI input - partial value returned
                    (TokenId::from(2), TotalKind::Sci, (150) as i64),
                ],
            },
        ];

        // Run tests
        for t in tests {
            println!("Running test: {:?}", t);

            // Setup verifier
            let mut report = TxSummaryUnblindingReport::<16>::default();
            let mut verifier = TxSummaryStreamingVerifierCtx::new(
                &[0u8; 32],
                BlockVersion::THREE,
                t.outputs.len(),
                t.inputs.len(),
                sender.view_private_key().clone(),
                PublicSubaddress {
                    view_public: change_subaddress.view_public_key().clone().into(),
                    spend_public: change_subaddress.spend_public_key().clone().into(),
                },
            );

            // Build and process TxOuts
            for (target, amount) in &t.outputs {
                println!("Add output {:?}: {:?}", target, amount);

                // Select target address
                let receive_subaddress = match target {
                    OutputTarget::Ourself => &sender_subaddress,
                    OutputTarget::Change => &change_subaddress,
                    OutputTarget::Other => &target_subaddress,
                    OutputTarget::Swap => &swap_subaddress,
                };

                // Setup keys for TxOut
                let tx_private_key = RistrettoPrivate::from_random(&mut rng);
                let txout_shared_secret =
                    create_shared_secret(receive_subaddress.view_public_key(), &tx_private_key);

                // Construct TxOut object
                let tx_out = TxOut::new(
                    BlockVersion::THREE,
                    amount.clone(),
                    &receive_subaddress,
                    &tx_private_key,
                    Default::default(),
                )
                .unwrap();

                // Build TxOut unblinding
                let masked_amount = tx_out.get_masked_amount().unwrap();
                let (amount, blinding) = masked_amount.get_value(&txout_shared_secret).unwrap();
                let unmasked_amount = UnmaskedAmount {
                    value: amount.value,
                    token_id: *amount.token_id,
                    blinding: blinding.into(),
                };

                // Build TxOut summary
                let target_key = create_tx_out_target_key(&tx_private_key, receive_subaddress);
                let tx_out_summary = TxOutSummary {
                    masked_amount: Some(masked_amount.clone()),
                    target_key: target_key.into(),
                    public_key: tx_out.public_key,
                    associated_to_input_rules: target == &OutputTarget::Swap,
                };

                // Set address for normal outputs, not provided for SCIs
                let address = match target != &OutputTarget::Swap {
                    true => Some((
                        ShortAddressHash::from(receive_subaddress),
                        receive_subaddress,
                    )),
                    false => None,
                };

                // Digest TxOout + Summary with verifier
                verifier
                    .digest_output(
                        &tx_out_summary,
                        &unmasked_amount,
                        address,
                        Some(&tx_private_key),
                        &mut report,
                    )
                    .unwrap();
            }

            // Build and process TxIns?
            for (kind, amount) in &t.inputs {
                println!("Add input: {:?}", amount);

                // Setup keys for TxOut (kx against sender key as this is an input)
                let tx_private_key = RistrettoPrivate::from_random(&mut rng);
                let txout_shared_secret =
                    create_shared_secret(sender_subaddress.view_public_key(), &tx_private_key);

                // Construct TxOut object
                let tx_out = TxOut::new(
                    BlockVersion::THREE,
                    amount.clone(),
                    &sender_subaddress,
                    &tx_private_key,
                    Default::default(),
                )
                .unwrap();

                let masked_amount = tx_out.get_masked_amount().unwrap();

                // Build TxIn summary
                let input_rules_digest = match kind {
                    InputType::Owned => Vec::new(),
                    InputType::Sci => vec![0u8; 32],
                };
                let tx_in_summary = TxInSummary {
                    pseudo_output_commitment: masked_amount.commitment().clone(),
                    input_rules_digest,
                };

                // Build TxIn unblinding
                let (amount, blinding) = masked_amount.get_value(&txout_shared_secret).unwrap();
                let unmasked_amount = UnmaskedAmount {
                    value: amount.value,
                    token_id: *amount.token_id,
                    blinding: blinding.into(),
                };

                // Digest transaction input
                verifier
                    .digest_input(&tx_in_summary, &unmasked_amount, &mut report)
                    .unwrap();
            }

            // Finalize verifier
            let mut digest = [0u8; 32];
            verifier
                .finalize(Amount::new(fee, token_id), 1234, &mut digest, &mut report)
                .unwrap();

            report.finalize().unwrap();

            // Check report totals
            let totals: Vec<_> = report.totals.iter().map(|(t, k, v)| (*t, *k, *v)).collect();
            assert_eq!(&totals, &t.totals, "Total mismatch");

            // Check report outputs
            let changes: Vec<_> = report
                .outputs
                .iter()
                .map(|(e, t, v)| (e.clone(), *t, *v))
                .collect();
            assert_eq!(&changes, &t.changes, "Output mismatch");
        }
    }
}
