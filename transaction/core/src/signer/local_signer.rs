// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{Error, OneTimeKeyDeriveData, RingSigner, SignableInputRing};
use crate::{
    onetime_keys::recover_onetime_private_key,
    ring_signature::{generators, CryptoRngCore, RingMLSAG, Scalar},
};
use mc_account_keys::AccountKey;
use mc_crypto_keys::RistrettoPublic;

/// An implementation of RingSigner that holds private keys and derives one-time
/// private keys
#[derive(Clone, Debug)]
pub struct LocalRingSigner {
    key: AccountKey,
}

impl RingSigner for LocalRingSigner {
    fn sign(
        &self,
        message: &[u8],
        ring: &SignableInputRing,
        pseudo_output_blinding: Scalar,
        rng: &mut dyn CryptoRngCore,
    ) -> Result<RingMLSAG, Error> {
        let real_input = ring
            .members
            .get(ring.real_input_index)
            .ok_or(Error::RealInputIndexOutOfBounds)?;
        let target_key = RistrettoPublic::try_from(&real_input.target_key)?;

        // First, compute the one-time private key
        let onetime_private_key = match ring.input_secret.onetime_key_derive_data {
            OneTimeKeyDeriveData::OneTimeKey(key) => key,
            OneTimeKeyDeriveData::SubaddressIndex(subaddress_index) => {
                let public_key = RistrettoPublic::try_from(&real_input.public_key)?;

                recover_onetime_private_key(
                    &public_key,
                    self.key.view_private_key(),
                    &self.key.subaddress_spend_private(subaddress_index),
                )
            }
        };

        // Check if this is the correct one-time private key
        if RistrettoPublic::from(&onetime_private_key) != target_key {
            return Err(Error::TrueInputNotOwned);
        }

        // Note: Some implementations might be able to cache this generator
        let generator = generators(*ring.input_secret.amount.token_id);

        // Sign the MLSAG
        Ok(RingMLSAG::sign(
            message,
            &ring.members,
            ring.real_input_index,
            &onetime_private_key,
            ring.input_secret.amount.value,
            &ring.input_secret.blinding,
            &pseudo_output_blinding,
            &generator,
            rng,
        )?)
    }
}

impl From<&AccountKey> for LocalRingSigner {
    fn from(src: &AccountKey) -> Self {
        Self { key: src.clone() }
    }
}
