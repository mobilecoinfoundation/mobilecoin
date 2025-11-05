// Copyright (c) 2018-2025 The MobileCoin Foundation

use crate::{
    transaction_builder::create_output_with_fog_hint, MemoBuilder, ReservedSubaddresses,
    TxBuilderError, TxOutputsOrdering,
};
use alloc::vec::Vec;
use mc_account_keys::PublicAddress;
use mc_crypto_keys::RistrettoPrivate;
use mc_crypto_ring_signature_signer::RingSigner;
use mc_transaction_core::{
    encrypted_fog_hint::EncryptedFogHint,
    ring_ct::{InputRing, OutputSecret},
    tx::{Tx, TxIn, TxOut, TxPrefix},
    FeeMap, MemoContext, MemoPayload, NewMemoError,
};
use mc_transaction_extra::UnsignedTx;
use mc_transaction_summary::TxOutSummaryUnblindingData;
use mc_transaction_types::{Amount, BlockVersion, UnmaskedAmount};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// The information we need to build an output TxOut
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub enum TxBlueprintOutput {
    /// A normal output to a recipient public address
    Recipient {
        /// The recipient of the transaction.
        recipient: PublicAddress,

        /// The amount being sent.
        amount: Amount,

        /// The encrypted fog hint for the fog ingest server.
        e_fog_hint: EncryptedFogHint,

        /// The tx private key for the output.
        tx_private_key: RistrettoPrivate,
    },

    /// A change output
    Change {
        /// Destination of the change output
        change_destination: ReservedSubaddresses,

        /// The amount being sent.
        amount: Amount,

        /// The encrypted fog hint for the fog ingest server.
        e_fog_hint: EncryptedFogHint,

        /// The tx private key for the output.
        tx_private_key: RistrettoPrivate,
    },

    /// SCI Required Output
    Sci {
        /// The output
        output: TxOut,

        /// The unmasked amount
        unmasked_amount: UnmaskedAmount,
    },
}

/// Source material for an unsinged transaction.
///
/// A `TxBlueprint`contains all information needed to build an unsigned
/// transaction, which can then be signed.
///
/// The major difference between `TxBlueprint` and `UnsignedTx` is that
/// `TxBlueprint` does not contain the output `TxOut`s but instead contains the
/// information needed to build them.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxBlueprint {
    /// Transaction inputs
    pub inputs: Vec<TxIn>,

    /// Rings
    pub rings: Vec<InputRing>,

    /// Outputs
    pub outputs: Vec<TxBlueprintOutput>,

    /// Fee to be paid.
    pub fee: Amount,

    /// The block index at which this transaction is no longer valid.
    pub tombstone_block: u64,

    /// Block version
    pub block_version: BlockVersion,
}

impl TxBlueprint {
    /// Build an unsigned transaction from the blueprint.
    /// The memo builder is used to build the memos for the outputs.
    pub fn to_unsigned_tx<O: TxOutputsOrdering>(
        &self,
        mut memo_builder: impl MemoBuilder,
    ) -> Result<UnsignedTx, TxBuilderError> {
        // make sure that the memo builder
        // is initialized to the same fee as the transaction
        memo_builder.set_fee(self.fee)?;

        // Change outputs have to be built last because RTH change memos require knowing
        // the total output amount.
        let mut outputs = self.outputs.clone();
        outputs.sort_by_key(|x| match x {
            TxBlueprintOutput::Change { .. } => 1,
            _ => 0,
        });

        let mut outputs_and_secrets = outputs
            .into_iter()
            .map(|output| build_output(&mut memo_builder, self, output))
            .collect::<Result<Vec<_>, _>>()?;

        // Outputs are sorted according to the rule (but generally by public key)
        outputs_and_secrets.sort_by(|(a, _), (b, _)| O::cmp(&a.public_key, &b.public_key));

        let (outputs, tx_out_unblinding_data): (Vec<TxOut>, Vec<_>) =
            outputs_and_secrets.drain(..).unzip();

        let tx_prefix = TxPrefix::new(self.inputs.clone(), outputs, self.fee, self.tombstone_block);

        Ok(UnsignedTx {
            tx_prefix,
            rings: self.rings.clone(),
            tx_out_unblinding_data,
            block_version: self.block_version,
        })
    }

    /// A helper for converting a TxBlueprint into a signed transaction, by
    /// building an unsigned transaction and then signing it.
    pub fn sign<O: TxOutputsOrdering, S: RingSigner + ?Sized, RNG: CryptoRng + RngCore>(
        &self,
        signer: &S,
        memo_builder: impl MemoBuilder,
        rng: &mut RNG,
        fee_map: Option<&FeeMap>,
    ) -> Result<Tx, TxBuilderError> {
        Ok(self
            .to_unsigned_tx::<O>(memo_builder)?
            .sign(signer, fee_map, rng)?)
    }
}

fn build_output(
    mb: &mut impl MemoBuilder,
    unsigned_tx: &TxBlueprint,
    unsigned_output: TxBlueprintOutput,
) -> Result<(TxOut, TxOutSummaryUnblindingData), TxBuilderError> {
    let (tx_out, unblinding_data) = match unsigned_output {
        TxBlueprintOutput::Recipient {
            recipient,
            amount,
            e_fog_hint,
            tx_private_key,
        } => build_standard_output(
            unsigned_tx.block_version,
            amount,
            &recipient,
            e_fog_hint,
            |memo_ctxt| mb.make_memo_for_output(amount, &recipient, memo_ctxt),
            tx_private_key,
        )?,

        TxBlueprintOutput::Change {
            change_destination,
            amount,
            e_fog_hint,
            tx_private_key,
        } => build_standard_output(
            unsigned_tx.block_version,
            amount,
            &change_destination.change_subaddress,
            e_fog_hint,
            |memo_ctxt| mb.make_memo_for_change_output(amount, &change_destination, memo_ctxt),
            tx_private_key,
        )?,

        TxBlueprintOutput::Sci {
            output,
            unmasked_amount,
        } => {
            let unblinding_data = TxOutSummaryUnblindingData {
                unmasked_amount: unmasked_amount.clone(),
                address: None,
                tx_private_key: None,
            };

            (output, unblinding_data)
        }
    };

    if !unsigned_tx.block_version.mixed_transactions_are_supported()
        && unsigned_tx.fee.token_id != unblinding_data.unmasked_amount.token_id
    {
        return Err(TxBuilderError::MixedTransactionsNotAllowed(
            unsigned_tx.fee.token_id,
            unblinding_data.unmasked_amount.token_id.into(),
        ));
    }

    Ok((tx_out, unblinding_data))
}

fn build_standard_output(
    block_version: BlockVersion,
    amount: Amount,
    recipient: &PublicAddress,
    e_fog_hint: EncryptedFogHint,
    memo_fn: impl FnOnce(MemoContext) -> Result<MemoPayload, NewMemoError>,
    tx_private_key: RistrettoPrivate,
) -> Result<(TxOut, TxOutSummaryUnblindingData), TxBuilderError> {
    let (tx_out, shared_secret) = create_output_with_fog_hint(
        block_version,
        amount,
        recipient,
        e_fog_hint,
        memo_fn,
        &tx_private_key,
    )?;

    let (amount, blinding) = tx_out
        .get_masked_amount()
        .expect("TransactionBuilder created an invalid MaskedAmount")
        .get_value(&shared_secret)
        .expect("TransactionBuilder created an invalid Amount");
    let output_secret = OutputSecret { amount, blinding };

    let unblinding_data = TxOutSummaryUnblindingData {
        unmasked_amount: output_secret.into(),
        address: Some(recipient.clone()),
        tx_private_key: Some(tx_private_key),
    };

    Ok((tx_out, unblinding_data))
}
