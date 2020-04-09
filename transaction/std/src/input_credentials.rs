// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::TxBuilderError;
use keys::{RistrettoPrivate, RistrettoPublic};
use rand::Rng;
use rand_core::CryptoRng;
use std::convert::TryFrom;
use transaction::tx::{TxOut, TxOutMembershipProof};

/// Credentials required to construct a ring signature for an input.
#[derive(Clone, Debug)]
pub struct InputCredentials {
    /// A "ring" containing "mixins" and the one "real" TxOut to be spent.
    pub ring: Vec<TxOut>,

    /// Proof that each TxOut in `ring` is in the ledger.
    pub membership_proofs: Vec<TxOutMembershipProof>,

    /// Index in `ring` of the "real" output being spent.
    pub real_index: usize,

    /// Private key for the "real" output being spent.
    pub onetime_private_key: RistrettoPrivate,

    /// Public key of the transaction that created the "real" output being spent.
    pub real_output_public_key: RistrettoPublic,

    /// View private key for the address this input was sent to
    pub view_private_key: RistrettoPrivate,
}

impl InputCredentials {
    /// Creates an InputCredential instance used to create and sign an Input.
    ///
    /// # Arguments
    /// * `ring` - A "ring" of transaction outputs.
    /// * `membership_proofs` - Proof that each TxOut in `ring` is in the ledger.
    /// * `real_index` - Index in `ring` of the output being spent.
    /// * `onetime_private_key` - Private key for the output being spent.
    /// * `view_private_key` - The view private key belonging to the owner of the real output.
    /// * `rng` - Randomness.
    pub fn new<R: Rng + CryptoRng>(
        ring: Vec<TxOut>,
        membership_proofs: Vec<TxOutMembershipProof>,
        real_index: usize,
        onetime_private_key: RistrettoPrivate,
        view_private_key: RistrettoPrivate,
        rng: &mut R,
    ) -> Result<Self, TxBuilderError> {
        debug_assert_eq!(ring.len(), membership_proofs.len());

        let real_tx_out: TxOut = ring
            .get(real_index)
            .cloned()
            .ok_or(TxBuilderError::NoInputs)?;
        let real_output_public_key = RistrettoPublic::try_from(&real_tx_out.public_key)?;

        // Randomly shuffle the ring and the corresponding proofs. This ensures that the ordering
        // of mixins in the transaction will not depend on the user's implementation for obtaining
        // mixins.
        let (shuffled_ring, shuffled_membership_proofs): (Vec<TxOut>, Vec<TxOutMembershipProof>) = {
            use rand::seq::SliceRandom;
            let mut zipped: Vec<_> = ring
                .into_iter()
                .zip(membership_proofs.into_iter())
                .collect();
            let zipped_as_slice = zipped.as_mut_slice();
            zipped_as_slice.shuffle(rng);
            zipped.into_iter().unzip()
        };

        let shuffled_real_index = shuffled_ring
            .iter()
            .position(|tx_out| *tx_out == real_tx_out)
            .expect("The real tx_out must still exist after shuffling.");

        Ok(InputCredentials {
            ring: shuffled_ring,
            membership_proofs: shuffled_membership_proofs,
            real_index: shuffled_real_index,
            onetime_private_key,
            real_output_public_key,
            view_private_key,
        })
    }
}
