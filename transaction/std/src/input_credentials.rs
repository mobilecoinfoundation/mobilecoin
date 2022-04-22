// Copyright (c) 2018-2022 The MobileCoin Foundation

use crate::TxBuilderError;
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_transaction_core::{
    onetime_keys::create_shared_secret,
    ring_signature::{InputSecret, SignableInputRing},
    tx::{TxOut, TxOutMembershipProof},
    AmountError,
};
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

    /// TxOut shared secret
    pub tx_out_shared_secret: RistrettoPublic,
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

        Ok(InputCredentials {
            ring,
            membership_proofs,
            real_index,
            onetime_private_key,
            tx_out_shared_secret,
        })
    }
}

impl TryFrom<&InputCredentials> for SignableInputRing {
    type Error = AmountError;
    fn try_from(src: &InputCredentials) -> Result<SignableInputRing, AmountError> {
        let masked_amount = &src.ring[src.real_index].masked_amount;
        let (amount, blinding) = masked_amount.get_value(&src.tx_out_shared_secret)?;

        let input_secret = InputSecret {
            onetime_private_key: src.onetime_private_key,
            amount,
            blinding,
        };

        Ok(SignableInputRing {
            members: src
                .ring
                .iter()
                .map(|tx_out| (tx_out.target_key, tx_out.masked_amount.commitment))
                .collect(),
            real_input_index: src.real_index,
            input_secret,
            input_rules: None,
        })
    }
}

impl Zeroize for InputCredentials {
    fn zeroize(&mut self) {
        self.real_index.zeroize();
        self.onetime_private_key.zeroize();
    }
}

impl Drop for InputCredentials {
    fn drop(&mut self) {
        self.zeroize();
    }
}
