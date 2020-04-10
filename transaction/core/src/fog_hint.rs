// Copyright (c) 2018-2020 MobileCoin Inc.

//! Code for computing and decrypting fog hints

use crate::{
    account_keys::PublicAddress,
    encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
};
use core::convert::TryFrom;
use keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic, RISTRETTO_PUBLIC_LEN};
use mcserial::ReprBytes32;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FogHint {
    view_pubkey: CompressedRistrettoPublic, // aka A from cryptonote public address
}

// When account hints are encrypted we pad with a magic number in order to
// detect more easily when decryption failed
const MAGIC_NUMBER: u8 = 42;

// The ENCRYPTED_DISCOVERY_HINT is an ecies encryption of the data in account hint.
const FOG_HINT_DECRYPTED_LEN: usize = ENCRYPTED_FOG_HINT_LEN - ecies::ECIES_EXTRA_SPACE;
// The plaintext is, one curve point, plus some padding. There should be a nonzero amount of padding,
// but probably only 8 bytes is sufficient. The size of the field is set in ledger crate which is
// lower level than us, so we work backwards from their constant.
// If this constant is negative fail the build.
#[allow(unused)]
const FOG_HINT_PADDING_LEN: usize = FOG_HINT_DECRYPTED_LEN - keys::RISTRETTO_PUBLIC_LEN;

// Construct a (plaintext) FogHint appropriate to send to a PublicAddress
impl From<&PublicAddress> for FogHint {
    fn from(src: &PublicAddress) -> Self {
        Self {
            view_pubkey: CompressedRistrettoPublic::from(src.view_public_key()),
        }
    }
}

impl FogHint {
    pub fn new(view_pubkey: RistrettoPublic) -> Self {
        Self {
            view_pubkey: CompressedRistrettoPublic::from(view_pubkey),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ecies::Error> {
        Ok(Self {
            view_pubkey: CompressedRistrettoPublic::try_from(bytes).map_err(ecies::Error::Key)?,
        })
    }
    #[inline]
    pub fn to_bytes(&self) -> [u8; keys::RISTRETTO_PUBLIC_LEN] {
        self.view_pubkey.to_bytes()
    }

    /// Get the view pubkey
    #[inline]
    pub fn get_view_pubkey(&self) -> &CompressedRistrettoPublic {
        &self.view_pubkey
    }

    /// encrypt
    ///
    /// Called by sender (in sdk, tests)
    /// Given an rng, and ingest server public key,
    /// produce an encrypted fog hint to attach to the TXO
    ///
    /// The first 32 bytes of the output are the ECIES curve point
    /// The second 96 bytes are the payload B,C padded with 32 MAGIC_NUMBER bytes, encrypted
    /// using AES cipher (per ECIES design).
    /// The MAGIC_NUMBER permit us to unambiguously determine when the decryption failed
    /// due to i.e. key mismatch.
    ///
    /// # Arguments
    /// * rng (for encryption)
    /// * acct_server_pubkey (to encrypt against)
    ///
    /// # Returns
    /// * 128 byte payload, cannot fail
    #[inline]
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        ingest_server_pubkey: &RistrettoPublic,
        rng: &mut T,
    ) -> EncryptedFogHint {
        let plaintext = {
            let mut result = [MAGIC_NUMBER; FOG_HINT_DECRYPTED_LEN];
            result[0..RISTRETTO_PUBLIC_LEN].copy_from_slice(&self.view_pubkey.to_bytes());
            result
        };
        let mut ciphertext = [0u8; ENCRYPTED_FOG_HINT_LEN];
        ecies::encrypt_into(rng, ingest_server_pubkey, &plaintext, &mut ciphertext);
        EncryptedFogHint::from(&ciphertext)
    }

    /// decrypt
    ///
    /// Try to decrypt an encrypted payload onto this FogHint object.
    /// Fails if ECIES curve point is malformed, or the magic number is wrong.
    ///
    /// Note(chris): This is not constant time, but neither is ecies::decrypt right
    /// now, because it short-circuits if ECIES curve point is malformed.
    /// We need to re-evaluate later if that's a problem and refactor if so
    ///
    /// # Arguments
    /// * acct_server_private_key
    /// * 128 byte encrypted payload
    ///
    /// # Returns
    /// * Fog hint on success, ecies error otherwise
    pub fn decrypt(
        ingest_server_private_key: &RistrettoPrivate,
        ciphertext: &EncryptedFogHint,
    ) -> Result<Self, ecies::Error> {
        let mut temp = [0u8; FOG_HINT_DECRYPTED_LEN];
        ecies::decrypt_into(ingest_server_private_key, ciphertext.as_ref(), &mut temp)?;
        // Check magic numbers
        for byte in &temp[RISTRETTO_PUBLIC_LEN..FOG_HINT_DECRYPTED_LEN] {
            if *byte != MAGIC_NUMBER {
                // TODO: better error code
                return Err(ecies::Error::MacFailed);
            }
        }
        FogHint::from_slice(&temp[0..RISTRETTO_PUBLIC_LEN])
    }
}

// tests

#[cfg(test)]
mod testing {
    use super::*;
    use keys::FromRandom;

    fn random_fog_hint<T: RngCore + CryptoRng>(rng: &mut T) -> FogHint {
        let view = RistrettoPublic::from_random(rng);
        FogHint::new(view)
    }

    #[test]
    fn test_round_trip() {
        test_helper::run_with_several_seeds(|mut rng| {
            let z = RistrettoPrivate::from_random(&mut rng);
            let zpub = RistrettoPublic::from(&z);

            let fog_hint = random_fog_hint(&mut rng);
            let ciphertext = fog_hint.encrypt(&zpub, &mut rng);

            let result = FogHint::decrypt(&z, &ciphertext);
            assert_eq!(Ok(fog_hint), result);
        });
    }

    #[test]
    fn test_expected_failure() {
        test_helper::run_with_several_seeds(|mut rng| {
            let z = RistrettoPrivate::from_random(&mut rng);
            let zpub = RistrettoPublic::from(&z);

            let fog_hint = random_fog_hint(&mut rng);
            let ciphertext = fog_hint.encrypt(&zpub, &mut rng);

            let not_z = RistrettoPrivate::from_random(&mut rng);

            let result = FogHint::decrypt(&not_z, &ciphertext);
            assert_eq!(Err(ecies::Error::MacFailed), result);
        });
    }
}
