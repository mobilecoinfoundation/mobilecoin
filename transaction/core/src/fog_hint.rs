// Copyright (c) 2018-2021 The MobileCoin Foundation

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
use rand_core::{CryptoRng, RngCore};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

/// The size of the plaintext (with magic numbers) in a fog hint.
/// This is slightly larger than CompressedRistrettoPublic.
///
/// This type is pub because it is used in some tests in other crates
pub type PlaintextArray = GenericArray<
    u8,
    Diff<EncryptedFogHintSize, <VersionedCryptoBox as CryptoBox<Ristretto>>::FooterSize>,
>;

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
    /// * Encrypted fog hint payload, cannot fail
    pub fn encrypt<T: RngCore + CryptoRng>(
        &self,
        ingest_server_pubkey: &RistrettoPublic,
        rng: &mut T,
    ) -> EncryptedFogHint {
        let mut plaintext = PlaintextArray::default();

        plaintext[..RISTRETTO_PUBLIC_LEN].copy_from_slice(&self.view_pubkey.to_bytes());
        for byte in &mut plaintext[RISTRETTO_PUBLIC_LEN..] {
            *byte = MAGIC_NUMBER;
        }
        let bytes = VersionedCryptoBox::default()
            .encrypt_fixed_length(rng, ingest_server_pubkey, &plaintext)
            .expect("cryptobox encryption failed unexpectedly");
        plaintext.zeroize();
        EncryptedFogHint::from(bytes)
    }

    /// ct_decrypt
    ///
    /// Try to decrypt an encrypted payload onto this FogHint object in constant
    /// time. Fails if decryption fails, or the magic number is wrong.
    ///
    /// # Arguments
    /// * ingest_server_private_key
    /// * encrypted fog hint payload
    /// * default plaintext
    /// * initialized output FogHint
    ///
    /// # Returns
    /// * Choice(1) on success Choice(0) otherwise
    /// * self is only modified in the operation is successful
    #[inline(never)]
    pub fn ct_decrypt(
        ingest_server_private_key: &RistrettoPrivate,
        ciphertext: &EncryptedFogHint,
        output: &mut Self,
    ) -> Choice {
        let (mut success, mut plaintext): (Choice, PlaintextArray) =
            match VersionedCryptoBox::default()
                .decrypt_fixed_length(ingest_server_private_key, ciphertext.as_ref())
            {
                Ok((success, plaintext)) => (Choice::from(success), plaintext),
                Err(_) => {
                    // An error that we don't have to be constant time with respect to, since rust
                    // Result was used
                    return Choice::from(0);
                }
            };

        // Check magic numbers
        for byte in &plaintext[RISTRETTO_PUBLIC_LEN..] {
            success &= byte.ct_eq(&MAGIC_NUMBER);
        }

        // Write pubkey bytes to output if success is true, otherwise don't change
        // output
        let mut output_bytes = output.view_pubkey.to_bytes();
        for idx in 0..output_bytes.len() {
            output_bytes[idx].conditional_assign(&plaintext[idx], success);
        }
        output.view_pubkey = CompressedRistrettoPublic::try_from(output_bytes.as_slice()).expect("Converting from bytes to compressed ristretto doesn't fail if they have the right size");

        // Zeroize temporary buffers
        plaintext.zeroize();
        output_bytes.zeroize();
        success
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

            let mut output_fog_hint = random_fog_hint(&mut rng);

            let choice = FogHint::ct_decrypt(&z, &ciphertext, &mut output_fog_hint);

            assert!(bool::from(choice));
            assert_eq!(fog_hint, output_fog_hint);
        });
    }

    #[test]
    fn test_expected_failure() {
        mc_util_test_helper::run_with_several_seeds(|mut rng| {
            let z = RistrettoPrivate::from_random(&mut rng);
            let zpub = RistrettoPublic::from(&z);
            let not_z = RistrettoPrivate::from_random(&mut rng);

            let fog_hint = random_fog_hint(&mut rng);
            let ciphertext = fog_hint.encrypt(&zpub, &mut rng);

            let mut output_fog_hint = random_fog_hint(&mut rng);

            let choice = FogHint::ct_decrypt(&not_z, &ciphertext, &mut output_fog_hint);

            assert!(!bool::from(choice));
            assert!(fog_hint != output_fog_hint);
        });
    }
}
