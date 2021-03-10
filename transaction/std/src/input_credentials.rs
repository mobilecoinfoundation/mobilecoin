// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::TxBuilderError;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use std::convert::TryFrom;
use zeroize::Zeroize;

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

    /// Public key of the transaction that created the "real" output being
    /// spent.
    pub real_output_public_key: RistrettoPublic,

    /// View private key for the address this input was sent to
    pub view_private_key: RistrettoPrivate,
}

impl InputCredentials {
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
        onetime_private_key: RistrettoPrivate,
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

        Ok(InputCredentials {
            ring,
            membership_proofs,
            real_index,
            onetime_private_key,
            real_output_public_key,
            view_private_key,
        })
    }
}

impl Zeroize for InputCredentials {
    fn zeroize(&mut self) {
        self.onetime_private_key.zeroize();
        self.view_private_key.zeroize();
    }
}

impl Drop for InputCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}
