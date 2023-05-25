// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{
    domain_separators::{EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG, EXTENDED_MESSAGE_DOMAIN_TAG},
    tx::TxPrefix,
    BlockVersion, CompressedCommitment, TxSummary, TxSummaryNew,
};
use alloc::vec::Vec;
use mc_crypto_digestible::{DigestTranscript, Digestible, MerlinTranscript};
use mc_util_zip_exact::ZipExactError;

/// The MLSAG signing digest is the digest that MLSAGs actually sign
pub struct MLSAGSigningDigest(pub Vec<u8>);

/// The extended message digest (or, before block version 2, the extended
/// message)
pub struct ExtendedMessageDigest(pub Vec<u8>);

impl From<MLSAGSigningDigest> for Vec<u8> {
    fn from(src: MLSAGSigningDigest) -> Self {
        src.0
    }
}

impl From<ExtendedMessageDigest> for Vec<u8> {
    fn from(src: ExtendedMessageDigest) -> Self {
        src.0
    }
}

/// Compute the digest that mlsags should actually sign, depending on the block
/// version.
///
/// Arguments:
/// * block_version: the block version we are targetting
/// * tx_prefix: the tx prefix of the transaction
/// * pseudo_output_commitments: the pseudo_output_commitments of the
///   transaction
/// * range_proof_bytes: the bytes of a single range proof. this is used in
///   block version 2 before the mixed transactions feature, and must be empty
///   after block version 3.
/// * range_proofs: the bytes of multiple range proofs. This is used in block
///   block version 3 after mixed transactions feature, and must be empty before
///   block version 3.
///
/// Returns:
/// * The MLSAG Signing Digest
/// * The TxSummary
/// * The extended_message_digest.
///
/// TODO: When support for block version < 2 is deprecated,
/// we can make this return `[u8; 32]` instead of Vec<u8>, which is nicer for
/// the hardware wallet implementation.
pub fn compute_mlsag_signing_digest(
    block_version: BlockVersion,
    tx_prefix: &TxPrefix,
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
    range_proofs: &[Vec<u8>],
) -> Result<(MLSAGSigningDigest, TxSummary, ExtendedMessageDigest), ZipExactError> {
    // The historical "message" is the tx_prefix hash
    let message = tx_prefix.hash();
    // The historical extended message
    let extended_message = compute_extended_message_either_version(
        block_version,
        &message,
        pseudo_output_commitments,
        range_proof_bytes,
        range_proofs,
    );

    // Make the TxSummary
    let tx_summary = TxSummary::new(tx_prefix, pseudo_output_commitments)?;

    // When the tx summary is also supposed to be part of the digest (to support
    // hardware wallets, we do another round of merlin using the previous digest
    // as the starting point, and then digest the TxSummary.
    // The TxSummary is much smaller than the entire Tx, so this last digest
    // can be reproduced on the hardware wallet with relative ease, compared to
    // trying to reproduce the entire extended message digest.
    let mlsag_signing_digest = if block_version.mlsags_sign_extended_message_and_tx_summary_digest()
    {
        let mut transcript =
            MerlinTranscript::new(EXTENDED_MESSAGE_AND_TX_SUMMARY_DOMAIN_TAG.as_bytes());
        extended_message
            .0
            .append_to_transcript(b"extended_message", &mut transcript);
        tx_summary.append_to_transcript(b"tx_summary", &mut transcript);

        // Extract digest
        let mut output = [0u8; 32];
        transcript.extract_digest(&mut output);
        MLSAGSigningDigest(output.to_vec())
    } else {
        // Bfore the extended_message_and_tx_summary_digest, mlsags sign the extended
        // message digest
        MLSAGSigningDigest(extended_message.0.clone())
    };

    Ok((mlsag_signing_digest, tx_summary, extended_message))
}

/// Toggles between old-style and new-style extended message
///
/// Arguments:
/// * block_version: the block version we are targetting
/// * message: the digest of the tx_prefix
/// * pseudo_output_commitments: the pseudo_output_commitments of the
///   transaction
/// * range_proof_bytes: the bytes of a single range proof. this is used in
///   block version 2 before the mixed transactions feature, and must be empty
///   after block version 3.
/// * range_proofs: the bytes of multiple range proofs. This is used in block
///   block version 3 after mixed transactions feature, and must be empty before
///   block version 3.
///
/// Returns:
/// * In block version 2 and later, the 32-byte extended message digest
/// * In block version <= 1, the (many byte) extended message
///
/// TODO: When support for block version < 2 is deprecated,
/// we can make this return `[u8; 32]` instead, which is nicer for the hardware
/// wallet implementation.
fn compute_extended_message_either_version(
    block_version: BlockVersion,
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
    range_proofs: &[Vec<u8>],
) -> ExtendedMessageDigest {
    ExtendedMessageDigest(if block_version.mlsags_sign_extended_message_digest() {
        // New-style extended message using merlin
        digest_extended_message(
            message,
            pseudo_output_commitments,
            range_proof_bytes,
            range_proofs,
        )
        .to_vec()
    } else {
        // Old-style extended message
        extend_message(message, pseudo_output_commitments, range_proof_bytes)
    })
}

/// Computes the extended message digest (new in block version 2)
///
/// * message: the digest of the tx_prefix
/// * pseudo_output_commitments: the pseudo_output_commitments of the
///   transaction
/// * range_proof_bytes: the bytes of a single range proof. this is used in
///   block version 2 before the mixed transactions feature, and must be empty
///   after block version 3.
/// * range_proofs: the bytes of multiple range proofs. This is used in block
///   block version 3 after mixed transactions feature, and must be empty before
///   block version 3.
fn digest_extended_message(
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
    range_proofs: &[Vec<u8>],
) -> [u8; 32] {
    let mut transcript = MerlinTranscript::new(EXTENDED_MESSAGE_DOMAIN_TAG.as_bytes());
    message.append_to_transcript(b"message", &mut transcript);
    pseudo_output_commitments.append_to_transcript(b"pseudo_output_commitments", &mut transcript);
    range_proof_bytes.append_to_transcript_allow_omit(b"range_proof_bytes", &mut transcript);
    range_proofs.append_to_transcript_allow_omit(b"range_proofs", &mut transcript);

    let mut output = [0u8; 32];
    transcript.extract_digest(&mut output);
    output
}

/// Concatenates [message || pseudo_output_commitments || range_proof_bytes].
/// This is the "extended message", which is signed by MLSAG's before block
/// version 2.
fn extend_message(
    message: &[u8],
    pseudo_output_commitments: &[CompressedCommitment],
    range_proof_bytes: &[u8],
) -> Vec<u8> {
    let mut extended_message: Vec<u8> = Vec::with_capacity(
        message.len() + pseudo_output_commitments.len() * 32 + range_proof_bytes.len(),
    );
    extended_message.extend_from_slice(message);
    for commitment in pseudo_output_commitments {
        extended_message.extend_from_slice(commitment.as_ref());
    }
    extended_message.extend_from_slice(range_proof_bytes);
    extended_message
}
