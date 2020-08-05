// Copyright (c) 2018-2020 MobileCoin Inc.

//! Code for computing and decrypting fog hints

use crate::encrypted_fog_hint::{EncryptedFogHint, EncryptedFogHintSize};
use core::convert::TryFrom;
use mc_account_keys::PublicAddress;
use mc_crypto_box::{
    generic_array::{
        typenum::{Diff, Unsigned},
        GenericArray,
    },
    CryptoBox, Error as CryptoBoxError, VersionedCryptoBox,
};
use mc_crypto_keys::{
    CompressedRistrettoPublic, ReprBytes, Ristretto, RistrettoPrivate, RistrettoPublic,
};
use mc_crypto_rand::McRng;
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FogHint {
    view_pubkey: CompressedRistrettoPublic, // aka A from cryptonote public address
}

// When account hints are encrypted we pad with a magic number in order to
// detect more easily when decryption failed
const MAGIC_NUMBER: u8 = 42;

// Save ourselves some typing
const RISTRETTO_PUBLIC_LEN: usize = <RistrettoPublic as ReprBytes>::Size::USIZE;

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
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoBoxError> {
        Ok(Self {
            view_pubkey: CompressedRistrettoPublic::try_from(bytes).map_err(CryptoBoxError::Key)?,
        })
    }
    pub fn to_bytes(&self) -> [u8; RISTRETTO_PUBLIC_LEN] {
        *self.view_pubkey.as_bytes()
    }

    /// Get the view pubkey
    pub fn get_view_pubkey(&self) -> &CompressedRistrettoPublic {
        &self.view_pubkey
    }

    /// encrypt
    ///
    /// Called by sender (in sdk, tests)
    /// Given an rng, and ingest server public key,
    /// produce an encrypted fog hint to attach to the TXO
    ///
    /// The first 32 bytes of the plaintext are the FogHint curvepoint
    /// The MAGIC_NUMBER help us to determine when the decryption failed
    ///
    /// # Arguments
    /// * rng (for encryption)
    /// * ingest_server_pubkey (to encrypt against)
    ///
    /// # Returns
    /// * 128 byte payload, cannot fail
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        ingest_server_pubkey: &RistrettoPublic,
        rng: &mut T,
    ) -> EncryptedFogHint {
        let mut plaintext = GenericArray::<
            u8,
            Diff<EncryptedFogHintSize, <VersionedCryptoBox as CryptoBox<Ristretto>>::FooterSize>,
        >::default();
        plaintext.as_mut()[..RISTRETTO_PUBLIC_LEN].copy_from_slice(&self.view_pubkey.to_bytes());
        for byte in &mut plaintext.as_mut()[RISTRETTO_PUBLIC_LEN..] {
            *byte = MAGIC_NUMBER;
        }
        let bytes = VersionedCryptoBox::default()
            .encrypt_fixed_length(rng, ingest_server_pubkey, &plaintext)
            .expect("cryptobox encryption failed unexpectedly");
        EncryptedFogHint::from(bytes)
    }

    /// decrypt
    ///
    /// Try to decrypt an encrypted payload onto this FogHint object.
    /// Fails if decryption fails, or the magic number is wrong.
    ///
    /// # Arguments
    /// * acct_server_private_key
    /// * 128 byte encrypted payload
    ///
    /// # Returns
    /// * Fog hint on success, cryptobox error otherwise
    pub fn decrypt(
        ingest_server_private_key: &RistrettoPrivate,
        ciphertext: &EncryptedFogHint,
    ) -> Result<Self, CryptoBoxError> {
        let plaintext = VersionedCryptoBox::default()
            .decrypt_fixed_length(ingest_server_private_key, ciphertext.as_ref())?;
        // Check magic numbers
        for byte in &plaintext[RISTRETTO_PUBLIC_LEN..] {
            if *byte != MAGIC_NUMBER {
                return Err(CryptoBoxError::WrongMagicBytes);
            }
        }
        FogHint::from_slice(&plaintext.as_ref()[0..RISTRETTO_PUBLIC_LEN])
    }

    /// ct_decrypt
    ///
    /// Try to decrypt an encrypted payload onto this FogHint object in constant time.
    /// Fails if decryption fails, or the magic number is wrong.
    ///
    /// # Arguments
    /// * ingest_server_private_key
    /// * 128 byte encrypted payload
    ///
    /// # Returns
    /// * (Fog hint, true) on success (Default Fog hint, false) otherwise
    pub fn ct_decrypt(
        ingest_server_private_key: &RistrettoPrivate,
        ciphertext: &EncryptedFogHint,
    ) -> (Self, bool) {
        let mut default_plaintext = GenericArray::<
            u8,
            Diff<EncryptedFogHintSize, <VersionedCryptoBox as CryptoBox<Ristretto>>::FooterSize>,
        >::default();

        let mut rng = McRng::default();
        let default_pubkey = RistrettoPublic::from_random(&mut rng);

        default_plaintext.as_mut()[..RISTRETTO_PUBLIC_LEN]
            .copy_from_slice(&default_pubkey.to_bytes());

        let (plaintext, mut success) = match VersionedCryptoBox::default()
            .decrypt_fixed_length(ingest_server_private_key, ciphertext.as_ref())
        {
            Ok(real_plaintext) => (real_plaintext, true),
            Err(_) => (default_plaintext, false),
        };

        // Check magic numbers
        for byte in &plaintext[RISTRETTO_PUBLIC_LEN..] {
            if *byte != MAGIC_NUMBER {
                success = false;
            }
        }

        let default_fog_hint = FogHint::new(default_pubkey);

        match FogHint::from_slice(&plaintext.as_ref()[0..RISTRETTO_PUBLIC_LEN]) {
            Ok(fog_hint) => (fog_hint, success),
            Err(_) => (default_fog_hint, false),
        }
    }
}

// tests

#[cfg(test)]
mod testing {
    use super::*;
    use mc_util_from_random::FromRandom;

    fn random_fog_hint<T: RngCore + CryptoRng>(rng: &mut T) -> FogHint {
        let view = RistrettoPublic::from_random(rng);
        FogHint::new(view)
    }

    #[test]
    fn test_round_trip() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
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
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let z = RistrettoPrivate::from_random(&mut rng);
            let zpub = RistrettoPublic::from(&z);

            let fog_hint = random_fog_hint(&mut rng);
            let ciphertext = fog_hint.encrypt(&zpub, &mut rng);

            let not_z = RistrettoPrivate::from_random(&mut rng);

            let result = FogHint::decrypt(&not_z, &ciphertext);
            assert_eq!(Err(CryptoBoxError::MacFailed), result);
        });
    }
}
