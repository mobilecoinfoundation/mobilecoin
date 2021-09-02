// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::user_rng_set::TxOutRecoveryError;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use mc_account_keys::AccountKey;
use mc_crypto_box::{CryptoBox, VersionedCryptoBox};
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_fog_types::view::TxOutRecord;
use mc_transaction_core::fog_hint::FogHint;
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// User's private keys (the only ones relevant to fog server)
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserPrivate {
    view_key: RistrettoPrivate,
}
impl Eq for UserPrivate {}

impl PartialEq for UserPrivate {
    fn eq(&self, other: &Self) -> bool {
        let self_pubkey = RistrettoPublic::from(&self.view_key);
        let other_pubkey = RistrettoPublic::from(&other.view_key);
        self_pubkey.eq(&other_pubkey)
    }
}

impl Hash for UserPrivate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let pubkey = RistrettoPublic::from(&self.view_key);
        pubkey.hash(state);
    }
}

impl UserPrivate {
    #[inline]
    pub fn new(view_key: RistrettoPrivate) -> Self {
        Self { view_key }
    }

    /// Make a random user (random private key)
    #[inline]
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self {
            view_key: RistrettoPrivate::from_random(rng),
        }
    }

    /// Get private key b
    #[inline]
    pub fn get_view_key(&self) -> &RistrettoPrivate {
        &self.view_key
    }

    /// Get public key B
    #[inline]
    pub fn get_view_pubkey(&self) -> RistrettoPublic {
        RistrettoPublic::from(&self.view_key)
    }

    /// Form the account hint for this user
    #[inline]
    pub fn get_hint(&self) -> FogHint {
        FogHint::new(self.get_view_pubkey())
    }

    /// Extract a TxOutRecord from an encrypted TxOutRecord from the view
    /// server, or return an error
    #[inline]
    pub fn decrypt_tx_out_result(
        &self,
        mut payload: Vec<u8>,
    ) -> Result<TxOutRecord, TxOutRecoveryError> {
        let success = VersionedCryptoBox::default()
            .decrypt_in_place(self.get_view_key(), &mut payload)
            .map_err(TxOutRecoveryError::DecryptionFailed)?;
        if !bool::from(success) {
            payload.zeroize();
            return Err(TxOutRecoveryError::MacCheckFailed);
        }

        let txo: TxOutRecord = mc_util_serial::decode(&payload)
            .map_err(|_| TxOutRecoveryError::TxOutRecordDeserializationFailed)?;
        Ok(txo)
    }
}

/// For fog users, we expect that the default subaddress is the public address
/// that they will distribute to be paid at. Then, when talking to fog, they
/// need to get the private view key corresponding to that public address that
/// they distributed.
///
/// We need to calculate the private key `c` corresponding to the public view
/// key 'C' Before subaddresses, this was simply `a`, which is part of the
/// account key.  Now it is `c = a(b + m)` where `m = Hs(a || subaddress_index)`
impl From<&AccountKey> for UserPrivate {
    fn from(src: &AccountKey) -> UserPrivate {
        UserPrivate {
            view_key: src.default_subaddress_view_private(),
        }
    }
}

#[cfg(test)]
mod testing {
    use super::*;
    use core::convert::TryFrom;
    use mc_crypto_box::{CryptoBox, VersionedCryptoBox};
    use mc_crypto_keys::CompressedRistrettoPublic;
    use mc_fog_types::view::{FogTxOut, FogTxOutMetadata};
    use mc_transaction_core::{fog_hint::FogHint, tx::TxOut};
    pub use rand_core::{CryptoRng, RngCore, SeedableRng};
    use rand_hc::Hc128Rng;

    /// Test that the private key that Bob uses with fog TxoFinder matches
    /// the public key that alice uses in fog hints
    #[test]
    fn test_fog_hint_construction() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let bob_keys = AccountKey::random(&mut rng);
            let hint_for_bob = FogHint::from(&bob_keys.default_subaddress());
            let bob_fog_credential = UserPrivate::from(&bob_keys);

            assert_eq!(
                CompressedRistrettoPublic::from(bob_fog_credential.get_view_pubkey()),
                *hint_for_bob.get_view_pubkey()
            );
        })
    }

    #[test]
    fn test_tx_row_encryption() {
        let mut rng = Hc128Rng::from_seed([1u8; 32]);

        // Typically loads public address from pubfile
        let recipient = AccountKey::random_with_fog(&mut rng);
        let hint = FogHint::new(*recipient.default_subaddress().view_public_key());
        let ingest_private = RistrettoPrivate::from_random(&mut rng);

        // Ingest publishes pubkey
        let ingest_public = RistrettoPublic::from(&ingest_private);

        // Arbitrary TxOut
        let tx_private_key = RistrettoPrivate::from_random(&mut rng);
        let txo = TxOut::new(
            10,
            &recipient.default_subaddress(),
            &tx_private_key,
            hint.encrypt(&ingest_public, &mut rng),
        )
        .unwrap();

        // Ingest decrypts the hint from the txo hint field
        let mut decrypted_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
        let success = FogHint::ct_decrypt(&ingest_private, &txo.e_fog_hint, &mut decrypted_hint);
        assert_eq!(hint, decrypted_hint);
        assert!(bool::from(success));

        // Prep for DB record
        let fog_txout = FogTxOut::from(&txo);
        let meta = FogTxOutMetadata {
            global_index: 1,
            block_index: 1,
            timestamp: 42,
        };
        let txo_record = TxOutRecord::new(fog_txout, meta);

        let protobuf = mc_util_serial::encode(&txo_record);

        // Encrypt with user_id.get_view_pubkey()
        let payload = VersionedCryptoBox::default()
            .encrypt(
                &mut rng,
                &RistrettoPublic::try_from(decrypted_hint.get_view_pubkey()).unwrap(),
                &protobuf,
            )
            .expect("CryptoBox encryption should not fail");

        // Client decrypts with key loaded from file
        let (_result, plaintext) = VersionedCryptoBox::default()
            .decrypt(&recipient.default_subaddress_view_private(), &payload)
            .expect("Could not decrypt cryptogram");
        assert_eq!(plaintext, protobuf);
    }
}
