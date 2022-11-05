// Copyright (c) 2018-2022 The MobileCoin Foundation

use alloc::vec::Vec;
use mc_crypto_ring_signature_signer::RingSigner;
use mc_transaction_core::{
    ring_ct::{
        Error as RingCtError, ExtendedMessageDigest, InputRing, OutputSecret,
        SignatureRctBulletproofs, SigningData,
    },
    tx::{Tx, TxPrefix},
    TxSummary,
};
use mc_transaction_types::{Amount, BlockVersion, TokenId};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A structure containing an unsigned transaction, together with the data
/// required to sign it that does not involve the spend private key.
/// The idea is that this can be generated without having the spend private key,
/// and then transferred to an offline/hardware service that does have the spend
/// private key, which can then be used together with the data here to produce a
/// valid, signed Tx. Noet that whether the UnsignedTx can be signed on its own
/// or requires the spend private key will depend on the contents of the
/// InputRings.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnsignedTx {
    /// The fully constructed TxPrefix.
    pub tx_prefix: TxPrefix,

    /// rings
    pub rings: Vec<InputRing>,

    /// Output secrets
    pub output_secrets: Vec<OutputSecret>,

    /// Block version
    pub block_version: BlockVersion,
}

impl UnsignedTx {
    /// Sign the transaction signing data with a given signer
    pub fn sign<RNG: CryptoRng + RngCore, S: RingSigner + ?Sized>(
        &self,
        signer: &S,
        rng: &mut RNG,
    ) -> Result<Tx, RingCtError> {
        let prefix = self.tx_prefix.clone();
        let signature = SignatureRctBulletproofs::sign(
            self.block_version,
            &prefix,
            self.rings.as_slice(),
            self.output_secrets.as_slice(),
            Amount::new(prefix.fee, TokenId::from(prefix.fee_token_id)),
            signer,
            rng,
        )?;

        Ok(Tx { prefix, signature })
    }

    /// Get prepared (but unsigned) ringct bulletproofs which can be signed
    /// later. Also gets the TxSummary and related digests.
    pub fn get_signing_data<RNG: CryptoRng + RngCore>(
        &self,
        rng: &mut RNG,
    ) -> Result<(SigningData, TxSummary, ExtendedMessageDigest), RingCtError> {
        let fee_amount = Amount::new(
            self.tx_prefix.fee,
            TokenId::from(self.tx_prefix.fee_token_id),
        );
        SigningData::new_with_summary(
            self.block_version,
            &self.tx_prefix,
            &self.rings,
            &self.output_secrets,
            fee_amount,
            true,
            rng,
        )
    }
}
