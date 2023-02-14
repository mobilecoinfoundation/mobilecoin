// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module provides support for a "streaming" verifier which consumes an
//! extended-message digest, a TxSummary and a TxSummaryUnblindingData,
//! in a piece-wise fashion, and produces an extended-message-and-tx-summary
//! digest, as well as a verified TxSummaryReport which contains the balance
//! deltas for all parties to the transaction.
//!
//! The streaming verifier itself occupies about 1200 bytes on the stack.
//! To take the largest "step" (verifying an output) requires
//! approximately 300 bytes + Fog url length

use super::{
    Error, TransactionEntity, TxOutSummaryUnblindingData, TxSummaryUnblindingData,
    TxSummaryUnblindingReport,
};
use mc_core::account::{RingCtAddress, ShortAddressHash};
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature::{
    onetime_keys::{create_shared_secret, create_tx_out_public_key, create_tx_out_target_key},
    CompressedCommitment,
};
use mc_transaction_types::{
    amount::{Amount, AmountError},
    domain_separators::EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG,
    masked_amount::MaskedAmount,
    tx_summary::{TxInSummary, TxOutSummary, TxSummary},
    unmasked_amount::UnmaskedAmount,
    BlockVersion,
};
use mc_util_zip_exact::zip_exact;

/// Exercise the functionality of the streaming verifier, and return its
/// results.
///
/// This is mainly useful for testing / demonstration purposes, since the more
/// interesting use-case is when the streaming verifier is on a small remote
/// device and doesn't have the full TxSummary or TxSummaryUnblindingData on
/// hand.
pub fn verify_tx_summary(
    extended_message_digest: &[u8; 32],
    tx_summary: &TxSummary,
    unblinding_data: &TxSummaryUnblindingData,
    view_private_key: RistrettoPrivate,
) -> Result<([u8; 32], TxSummaryUnblindingReport), Error> {
    let mut verifier = TxSummaryStreamingVerifier::new(
        extended_message_digest,
        unblinding_data.block_version.try_into()?,
        tx_summary.outputs.len(),
        tx_summary.inputs.len(),
        view_private_key,
    );
    for (tx_out_summary, tx_out_unblinding_data) in
        zip_exact(tx_summary.outputs.iter(), unblinding_data.outputs.iter())?
    {
        let TxOutSummaryUnblindingData {
            unmasked_amount,
            address,
            tx_private_key,
        } = tx_out_unblinding_data;
        let address = address.as_ref().map(|v| (ShortAddressHash::from(v), v));

        verifier.digest_output(
            tx_out_summary,
            unmasked_amount,
            address,
            tx_private_key.as_ref(),
        )?;
    }
    for (tx_in_summary, tx_in_unblinding_data) in
        zip_exact(tx_summary.inputs.iter(), unblinding_data.inputs.iter())?
    {
        verifier.digest_input(tx_in_summary, tx_in_unblinding_data)?;
    }
    let (digest, report) = verifier.finalize(
        Amount::new(tx_summary.fee, tx_summary.fee_token_id.into()),
        tx_summary.tombstone_block,
    )?;

    // In a debug build, confirm the digest by computing it in a non-streaming way
    //
    // Note: this needs to be kept in sync with the compute_mlsag_signing_digest
    // function in transaction_core::ring_ct::rct_bulletproofs
    #[cfg(debug)]
    {
        let mut transcript =
            MerlinTranscript::new(EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG.as_bytes());
        extended_message.append_to_transcript(b"extended_message", &mut transcript);
        tx_summary.append_to_transcript(b"tx_summary", &mut transcript);

        // Extract digest
        let mut output = [0u8; 32];
        transcript.extract_digest(&mut output);

        assert_eq!(
            output, digest,
            "streaming verifier did not compute correct digest"
        );
    }
    Ok((digest, report))
}

/// An object intended for hardware wallets to use, with a dual purpose.
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
/// The TxSummaryUnblindingReport can be displayed to the hardware wallet user,
/// and then if they approve, Ring MLSAGs can be signed over the digest produced
/// by this verifier, knowing what the significance of signing these is.
///
/// Note: The TxSummaryUnblindingReport makes assumptions about the details
/// of how a TxSummary and its constituents digested. These are currently
/// implementation details of the mc-crypto-digestible scheme.
/// If TxSummary digestible annotations are changed then this object's
/// implementation needs to change also.
pub struct TxSummaryStreamingVerifier {
    // The account view private key of the transaction signer.
    // This is used to identify outputs addressed to ourselves regardless of subaddress
    view_private_key: RistrettoPrivate,
    // The block version that this transaction is targetting
    block_version: BlockVersion,
    // The merlin transcript which we maintain in order to produce the digest
    // at the end.
    transcript: MerlinTranscript,
    // The report which we produce about what balance changes occur for what
    // parties
    report: TxSummaryUnblindingReport,
    // The total number of outputs expected
    expected_num_outputs: usize,
    // The total number of inputs expected
    expected_num_inputs: usize,
    // The count of outputs we have already seen
    output_count: usize,
    // The count of inputs we have already seen
    input_count: usize,
}

impl TxSummaryStreamingVerifier {
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
    ) -> Self {
        let mut transcript =
            MerlinTranscript::new(EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG.as_bytes());
        extended_message_digest.append_to_transcript(b"extended_message", &mut transcript);

        // Append start of TxSummary object
        transcript.append_agg_header(b"tx_summary", b"TxSummary");
        // Append start of TxSummary.outputs list
        transcript.append_seq_header(b"outputs", expected_num_outputs);

        // Default initialize the report
        let report = TxSummaryUnblindingReport::default();
        Self {
            view_private_key,
            block_version,
            transcript,
            report,
            expected_num_outputs,
            expected_num_inputs,
            output_count: 0,
            input_count: 0,
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
    ) -> Result<(), Error> {
        if self.output_count >= self.expected_num_outputs {
            return Err(Error::UnexpectedOutput);
        }

        // Now try to verify the recipient. This is either ourselves, or someone else
        // with the listed address, or this is associated to an SCI.
        if let Some(amount) = self.view_key_match(tx_out_summary)? {
            // If we view-key matched the output, then it belongs to one of our subaddresses
            self.report
                .balance_add(TransactionEntity::Ourself, amount.token_id, amount.value)?;
        } else if let Some((address_hash, address)) = address.as_ref() {
            let amount = Amount::new(unmasked_amount.value, unmasked_amount.token_id.into());
            // In this case, we are given the address of who is supposed to have received
            // this.
            let tx_private_key = tx_private_key.as_ref().ok_or(Error::MissingTxPrivateKey)?;
            // Let's try to verify that the TxOutSummary is as expected
            let expected =
                Self::expected_tx_out_summary(self.block_version, amount, address, tx_private_key)?;
            if &expected == tx_out_summary {
                self.report.balance_add(
                    TransactionEntity::Address(address_hash.clone()),
                    amount.token_id,
                    amount.value,
                )?;
            } else {
                return Err(Error::AddressVerificationFailed);
            }
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
            self.report
                .balance_add(TransactionEntity::Swap, token_id.into(), value)?;
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
        let entity = if tx_in_summary.input_rules_digest.is_empty() {
            TransactionEntity::Ourself
        } else {
            TransactionEntity::Swap
        };

        self.report
            .balance_subtract(entity, token_id.into(), value)?;

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
    ) -> Result<([u8; 32], TxSummaryUnblindingReport), Error> {
        if self.output_count != self.expected_num_outputs {
            return Err(Error::StillExpectingMoreOutputs);
        }
        if self.input_count != self.expected_num_inputs {
            return Err(Error::StillExpectingMoreInputs);
        }

        self.report.network_fee = fee;
        self.report.tombstone_block = tombstone_block;
        self.report.sort();

        fee.value.append_to_transcript(b"fee", &mut self.transcript);
        (*fee.token_id).append_to_transcript(b"fee_token_id", &mut self.transcript);
        tombstone_block.append_to_transcript(b"tombstone_block", &mut self.transcript);

        // Append the closer of the TxSummary object
        self.transcript
            .append_agg_closer(b"tx_summary", b"TxSummary");

        // Extract the digest
        let mut digest = [0u8; 32];
        self.transcript.extract_digest(&mut digest);

        Ok((digest, self.report))
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

    // Test the size of the streaming verifier on the stack. This is using heapless.
    #[test]
    fn test_streaming_verifier_size() {
        assert_eq!(core::mem::size_of::<TxSummaryStreamingVerifier>(), 1600);
    }

    // Note: Most tests are in transaction/extra/tests to avoid build issues.
}
