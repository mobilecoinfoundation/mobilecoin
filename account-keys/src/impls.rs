//! Implement mc-abstract-account-keys traits for concrete AccountKeys

use crate::{AccountKeys};
use curve25519_dalek::scalar::Scalar;
use mc_abstract_account_keys::{RingSigner, MemoHmacSigner, KeyImageComputer, Error};
use mc_crypto_ring_signature::{KeyImage,SignableInputRing, onetime_keys::recover_onetime_private_key};

// Note: We should delete `LocalRingSigner` and just use `AccountKeys` where we were using that.
impl RingSinger for AccountKeys {
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
                    self.view_private_key(),
                    &self.subaddress_spend_private(subaddress_index),
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

impl MemoHmacSigner for AccountKeys {
    fn compute_memo_hmac_sig(&self, receiving_subaddress_view_public: &CompressedRistrettoPublic, tx_out_public_key: &CompressedRistrettoPublic, memo_type: &[u8; 2], memo_data_sans_hmac: &[u8; 48]) -> Result<[u8; 16], Error> {

        let shared_secret = self
            .subaddress_spend_private_key(DEFAULT_SUBADDRESS_INDEX)
            .key_exchange(receiving_subaddress_view_public_key);

        let hmac_value = compute_category1_hmac(
            shared_secret.as_ref(),
            tx_out_public_key,
            Self::MEMO_TYPE_BYTES,
            &memo_data_sans_hmac,
        );

        Ok(hmac_value)
    }        
}

impl KeyImageComputer for AccountKeys {
    fn compute_key_image(&self, tx_out_public_key: &CompressedRistrettoPublic, subaddress_index: u64) -> Result<KeyImage, Error> {
        let decompressed_tx_pub = RistrettoPublic::try_from(tx_out_public_key)?;

        let onetime_private_key = recover_onetime_private_key(
            &decompressed_tx_pub,
            self.view_private_key(),
            &self.subaddress_spend_private(subaddress_index),
        );
        Ok(KeyImage::from(&onetime_private_key));
    }
}
