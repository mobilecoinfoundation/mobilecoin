// Copyright (c) 2018-2023 The MobileCoin Foundation

use alloc::vec::Vec;

use super::{Error, TxSummaryUnblindingReport};
use crate::{report::TransactionReport, TxSummaryStreamingVerifierCtx};
use mc_account_keys::PublicAddress;
use mc_core::account::{PublicSubaddress, RingCtAddress, ShortAddressHash};
use mc_crypto_digestible::Digestible;
use mc_crypto_keys::RistrettoPrivate;
use mc_transaction_types::{Amount, TxSummary, UnmaskedAmount};
use mc_util_zip_exact::zip_exact;
#[cfg(feature = "prost")]
use prost::Message;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Unblinding data correpsonding to a TxSummary. This reveals the amounts of
/// all inputs and outputs in a way that can be confirmed against the TxSummary.
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
pub struct TxSummaryUnblindingData {
    /// The block version targetted by the outputs of this Tx
    #[cfg_attr(feature = "prost", prost(uint32, tag = "1"))]
    pub block_version: u32,

    /// A TxOutSummaryUnblindingData, one for each transaction output
    #[cfg_attr(feature = "prost", prost(message, repeated, tag = "2"))]
    pub outputs: Vec<TxOutSummaryUnblindingData>,

    /// An unmasked amount, one for each transaction input, corresponding to
    /// the pseudo-output commitment
    #[cfg_attr(feature = "prost", prost(message, repeated, tag = "3"))]
    pub inputs: Vec<UnmaskedAmount>,
}

/// Unblinding data corresponding to a TxOutSummary. This reveals the amount
/// and, usually, the Public Address to which this TxOut is addressed.
#[derive(Clone, Digestible, Eq, PartialEq, Zeroize)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "prost", derive(Message))]
#[cfg_attr(not(feature = "prost"), derive(Debug))]
pub struct TxOutSummaryUnblindingData {
    /// An unmasked amount, corresponding to the MaskedAmount field
    /// The block vesion appears in the TxSummaryUnblindingData.
    #[cfg_attr(feature = "prost", prost(message, required, tag = "1"))]
    pub unmasked_amount: UnmaskedAmount,

    /// The public address to which this TxOut is addressed.
    /// If this output comes from an SCI then we may not know the public
    /// address.
    #[cfg_attr(feature = "prost", prost(message, optional, tag = "2"))]
    pub address: Option<PublicAddress>,

    /// The tx_private_key generated for this TxOut. This is an entropy source
    /// which introduces randomness into the cryptonote stealth addresses
    /// (tx_public_key and tx_target_key) of the TxOut.
    ///
    /// If this output comes from an SCI then we may not know this.
    #[cfg_attr(feature = "prost", prost(message, optional, tag = "3"))]
    pub tx_private_key: Option<RistrettoPrivate>,
}

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
    change_address: impl RingCtAddress,
) -> Result<([u8; 32], TxSummaryUnblindingReport), Error> {
    let mut verifier = TxSummaryStreamingVerifierCtx::new(
        extended_message_digest,
        unblinding_data.block_version.try_into()?,
        tx_summary.outputs.len(),
        tx_summary.inputs.len(),
        view_private_key,
        PublicSubaddress {
            view_public: change_address.view_public_key(),
            spend_public: change_address.spend_public_key(),
        },
    );
    let mut report = TxSummaryUnblindingReport::default();

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
            &mut report,
        )?;
    }
    for (tx_in_summary, tx_in_unblinding_data) in
        zip_exact(tx_summary.inputs.iter(), unblinding_data.inputs.iter())?
    {
        verifier.digest_input(tx_in_summary, tx_in_unblinding_data, &mut report)?;
    }

    let mut digest = [0u8; 32];
    verifier.finalize(
        Amount::new(tx_summary.fee, tx_summary.fee_token_id.into()),
        tx_summary.tombstone_block,
        &mut digest,
        &mut report,
    )?;

    report.finalize()?;

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
