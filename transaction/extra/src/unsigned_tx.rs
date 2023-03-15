// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::{TxOutSummaryUnblindingData, TxSummaryUnblindingData};
use alloc::vec::Vec;
use mc_crypto_ring_signature_signer::RingSigner;
use mc_transaction_core::{
    ring_ct::{
        Error as RingCtError, ExtendedMessageDigest, InputRing, OutputSecret,
        SignatureRctBulletproofs, SigningData,
    },
    tx::{Tx, TxPrefix},
    FeeMap,
};
use mc_transaction_types::{Amount, BlockVersion, TokenId, TxSummary, UnmaskedAmount};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A structure containing an unsigned transaction, together with the data
/// required to sign it that does not involve the spend private key.
/// The idea is that this can be generated without having the spend private key,
/// and then transferred to an offline/hardware service that does have the spend
/// private key, which can then be used together with the data here to produce a
/// valid, signed Tx. Note that whether the UnsignedTx can be signed on its own
/// or requires the spend private key will depend on the contents of the
/// InputRings.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// The fully constructed TxPrefix.
    pub tx_prefix: TxPrefix,

    /// rings
    pub rings: Vec<InputRing>,

    /// Output secrets
    pub tx_out_unblinding_data: Vec<TxOutSummaryUnblindingData>,

    /// Block version
    pub block_version: BlockVersion,
}

impl UnsignedTx {
    /// Sign the transaction signing data with a given signer
    pub fn sign<RNG: CryptoRng + RngCore, S: RingSigner + ?Sized>(
        &self,
        signer: &S,
        fee_map: Option<&FeeMap>,
        rng: &mut RNG,
    ) -> Result<Tx, RingCtError> {
        let prefix = self.tx_prefix.clone();
        let output_secrets: Vec<OutputSecret> = self
            .tx_out_unblinding_data
            .iter()
            .map(|data| OutputSecret::from(data.unmasked_amount.clone()))
            .collect();
        let signature = SignatureRctBulletproofs::sign(
            self.block_version,
            &prefix,
            self.rings.as_slice(),
            output_secrets.as_slice(),
            Amount::new(prefix.fee, TokenId::from(prefix.fee_token_id)),
            signer,
            rng,
        )?;
        let fee_map_digest = fee_map
            .map(|fm| fm.canonical_digest().to_vec())
            .unwrap_or_default();

        Ok(Tx {
            prefix,
            signature,
            fee_map_digest,
        })
    }

    /// Get prepared (but unsigned) ringct bulletproofs which can be signed
    /// later. Also gets the TxSummary and related digests.
    ///
    /// Returns:
    /// * SigningData This is essentially all parts of SignatureRctBulletproofs
    ///   except the ring signatures
    /// * TxSummary This is a small snapshot of the Tx used by hardware wallets
    /// * TxSummaryUnblindingData
    /// * ExtendedMessageDigest This is a digest used in connection with the
    ///   TxSummary
    pub fn get_signing_data<RNG: CryptoRng + RngCore>(
        &self,
        rng: &mut RNG,
    ) -> Result<
        (
            SigningData,
            TxSummary,
            TxSummaryUnblindingData,
            ExtendedMessageDigest,
        ),
        RingCtError,
    > {
        let fee_amount = Amount::new(
            self.tx_prefix.fee,
            TokenId::from(self.tx_prefix.fee_token_id),
        );
        let output_secrets: Vec<OutputSecret> = self
            .tx_out_unblinding_data
            .iter()
            .map(|data| OutputSecret::from(data.unmasked_amount.clone()))
            .collect();
        let (signing_data, tx_summary, extended_message_digest) = SigningData::new_with_summary(
            self.block_version,
            &self.tx_prefix,
            &self.rings,
            &output_secrets,
            fee_amount,
            true,
            rng,
        )?;
        // Try to build the TxSummary unblinding data, which requires the amounts from
        // the rings, and the blinding factors from the signing data segment.
        if signing_data.pseudo_output_blindings.len() != self.rings.len() {
            return Err(RingCtError::LengthMismatch(
                signing_data.pseudo_output_blindings.len(),
                self.rings.len(),
            ));
        }
        let tx_summary_unblinding_data = TxSummaryUnblindingData {
            block_version: *self.block_version,
            outputs: self.tx_out_unblinding_data.clone(),
            inputs: signing_data
                .pseudo_output_blindings
                .iter()
                .zip(self.rings.iter())
                .map(|(blinding, ring)| {
                    let amount = ring.amount();
                    UnmaskedAmount {
                        value: amount.value,
                        token_id: *amount.token_id,
                        blinding: (*blinding).into(),
                    }
                })
                .collect(),
        };
        Ok((
            signing_data,
            tx_summary,
            tx_summary_unblinding_data,
            extended_message_digest,
        ))
    }
}
