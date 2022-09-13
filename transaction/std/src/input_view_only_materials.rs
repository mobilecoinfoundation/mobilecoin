// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::TxBuilderError;
use curve25519_dalek::scalar::Scalar;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature_signer::ViewOnlyInputRing;
use mc_transaction_core::{
    onetime_keys::create_shared_secret,
    tx::{TxIn, TxOut, TxOutMembershipProof},
    TxOutConversionError,
};
use mc_transaction_types::Amount;
use zeroize::Zeroize;

/// Credentials required to construct a ring signature for an input.
#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct InputViewOnlyMaterials {
    /// A "ring" containing "mixins" and the one "real" TxOut to be spent.
    pub ring: Vec<TxOut>,

    /// Proof that each TxOut in `ring` is in the ledger.
    pub membership_proofs: Vec<TxOutMembershipProof>,

    /// Index in `ring` of the "real" output being spent.
    pub real_index: usize,

    /// Amount of the "real" output being spent.
    pub amount: Amount,

    /// The blinding factor of the output we are trying to spend
    pub blinding: Scalar,
}

impl InputViewOnlyMaterials {
    /// Creates an InputCredential instance used to create and sign an Input.
    ///
    /// # Arguments
    /// * `ring` - A "ring" of transaction outputs.
    /// * `membership_proofs` - Proof that each TxOut in `ring` is in the
    ///   ledger.
    /// * `real_index` - Index in `ring` of the output being spent.
    /// * `onetime_private_key` - Private key for the output being spent.
    /// * `view_private_key` - The view private key belonging to the owner of
    ///   the real output.
    pub fn new(
        ring: Vec<TxOut>,
        membership_proofs: Vec<TxOutMembershipProof>,
        real_index: usize,
        view_private_key: RistrettoPrivate,
    ) -> Result<Self, TxBuilderError> {
        debug_assert_eq!(ring.len(), membership_proofs.len());

        if real_index > ring.len() || ring.is_empty() {
            return Err(TxBuilderError::InvalidRingSize);
        }

        let real_input: TxOut = ring
            .get(real_index)
            .cloned()
            .ok_or(TxBuilderError::NoInputs)?;
        let real_output_public_key = RistrettoPublic::try_from(&real_input.public_key)?;

        // Note: The caller likely already has the shared secret if they already
        // unmasked this TxOut and are now trying to spend it, so as an
        // optimization we could avoid recomputing it.
        let tx_out_shared_secret = create_shared_secret(&real_output_public_key, &view_private_key);

        // Sort the ring and the corresponding proofs. This ensures that the ordering
        // of mixins in the transaction does not depend on the user's implementation for
        // obtaining mixins.
        let mut ring_and_proofs: Vec<(TxOut, TxOutMembershipProof)> = ring
            .into_iter()
            .zip(membership_proofs.into_iter())
            .collect();

        ring_and_proofs
            .sort_by(|(tx_out_a, _), (tx_out_b, _)| tx_out_a.public_key.cmp(&tx_out_b.public_key));

        let (ring, membership_proofs): (Vec<TxOut>, Vec<TxOutMembershipProof>) =
            ring_and_proofs.into_iter().unzip();

        let real_index: usize = ring
            .iter()
            .position(|element| *element == real_input)
            .expect("Must still contain real input");

        let masked_amount = &ring[real_index].get_masked_amount()?;
        let (amount, blinding) = masked_amount.get_value(&tx_out_shared_secret)?;

        Ok(InputViewOnlyMaterials {
            ring,
            membership_proofs,
            real_index,
            amount,
            blinding,
        })
    }
}

impl TryFrom<InputViewOnlyMaterials> for ViewOnlyInputRing {
    type Error = TxOutConversionError;

    fn try_from(src: InputViewOnlyMaterials) -> Result<Self, Self::Error> {
        Ok(ViewOnlyInputRing {
            members: src
                .ring
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            real_input_index: src.real_index,
            amount: src.amount,
            blinding: src.blinding,
        })
    }
}

impl From<&InputViewOnlyMaterials> for TxIn {
    fn from(input_view_only_materials: &InputViewOnlyMaterials) -> TxIn {
        TxIn {
            ring: input_view_only_materials.ring.clone(),
            proofs: input_view_only_materials.membership_proofs.clone(),
            input_rules: None,
        }
    }
}
