// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{BufferedRng, Error, KexRngCore, KexRngPubkey, NewFromKex, StoredRng};
use blake2::digest::generic_array::{typenum::Unsigned, GenericArray};
use core::convert::TryFrom;
use mc_crypto_keys::{Kex, KeyError};
use mc_util_repr_bytes::ReprBytes;
use rand_core::{CryptoRng, RngCore};

/// A KexRngCore plus an output buffer to allow peeking, and a counter to allow
/// knowing how many draws have been made. This allows to implement BufferedRng
pub struct BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    // The secret produced by key exchange, used as key to PRF
    // Note: here we assume that the represenation size of the secret
    // is the same as the size of the public key, which is true since they
    // are both "curve points" in a kex algorithm.
    secret: GenericArray<u8, <KexAlgo::Public as ReprBytes>::Size>,
    // The counter value used with PRF
    counter: u64,
    // A buffer to hold last output to allow peeking
    buffer: GenericArray<u8, <Core as KexRngCore<KexAlgo>>::OutputSize>,
}

////
// Implement high-level traits
////

impl<Core, KexAlgo> BufferedRng for BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    fn peek(&self) -> &[u8] {
        self.buffer.as_slice()
    }
    fn advance(&mut self) {
        self.counter += 1;
        self.buffer = Core::prf(&self.secret, &self.counter);
    }
    fn index(&self) -> u64 {
        self.counter
    }
    fn version_id(&self) -> u32 {
        Core::VERSION_ID
    }
}

// Initialization from a Kex::Secret
//
// Note: this cannot use the core::convert::From trait because it conflicts,
// according to rust's rules, some unknown KexAlgo may specify StoredRng as
// the Secret type.
impl<Core, KexAlgo> BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    pub fn from_secret(src: KexAlgo::Secret) -> Self {
        let secret = GenericArray::from_slice(src.as_ref()).clone();
        let counter = 0u64;
        let buffer = Core::prf(&secret, &counter);
        Self {
            secret,
            counter,
            buffer,
        }
    }
}

// Initialization via key exchange, by forwarding to core
impl<Core, KexAlgo> NewFromKex<KexAlgo> for BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
    for<'privkey> KexAlgo::Public: From<&'privkey KexAlgo::EphemeralPrivate>,
    for<'privkey> KexAlgo::Public: From<&'privkey KexAlgo::Private>,
{
    fn new_from_ephemeral_static<T: RngCore + CryptoRng>(
        rng: &mut T,
        pubkey: &KexAlgo::Public,
    ) -> (KexRngPubkey, Self) {
        use mc_crypto_keys::KexPublic;
        let (our_public, secret) = pubkey.new_secret(rng);
        let kex_pubkey = KexRngPubkey::from_public_key::<Core, KexAlgo>(&our_public);
        (kex_pubkey, Self::from_secret(secret))
    }

    fn new_from_static_static(
        our_private: &KexAlgo::Private,
        their_pubkey: &KexAlgo::Public,
    ) -> (KexRngPubkey, Self) {
        use mc_crypto_keys::KexReusablePrivate;
        let secret = our_private.key_exchange(their_pubkey);
        let kex_pubkey =
            KexRngPubkey::from_public_key::<Core, KexAlgo>(&KexAlgo::Public::from(our_private));
        (kex_pubkey, Self::from_secret(secret))
    }

    fn try_from_kex_pubkey(
        pubkey: &KexRngPubkey,
        our_private: &KexAlgo::Private,
    ) -> Result<Self, Error> {
        use mc_crypto_keys::KexReusablePrivate;
        if pubkey.version != <Core as KexRngCore<KexAlgo>>::VERSION_ID {
            return Err(Error::from(KeyError::AlgorithmMismatch));
        }
        let pubkey = KexAlgo::Public::try_from(&pubkey.public_key[..])?;
        let secret = our_private.key_exchange(&pubkey);
        Ok(Self::from_secret(secret))
    }
}

////
// Implement underlying required traits
////

// Clone
impl<Core, KexAlgo> Clone for BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            buffer: self.buffer.clone(),
            counter: self.counter,
        }
    }
}

// To Serialization Form
impl<Core, KexAlgo> From<BufferedKexRng<Core, KexAlgo>> for StoredRng
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    fn from(src: BufferedKexRng<Core, KexAlgo>) -> StoredRng {
        StoredRng {
            version: Core::VERSION_ID,
            secret: src.secret.as_slice().to_vec(),
            buffer: src.buffer.as_slice().to_vec(),
            counter: src.counter,
        }
    }
}

// From Serialization Form
impl<Core, KexAlgo> TryFrom<StoredRng> for BufferedKexRng<Core, KexAlgo>
where
    Core: KexRngCore<KexAlgo>,
    KexAlgo: Kex,
{
    type Error = KeyError;

    fn try_from(src: StoredRng) -> Result<Self, KeyError> {
        if src.version != Core::VERSION_ID {
            return Err(KeyError::AlgorithmMismatch);
        }
        if src.buffer.len() != Core::OutputSize::USIZE {
            return Err(KeyError::LengthMismatch(
                src.buffer.len(),
                Core::OutputSize::USIZE,
            ));
        }
        if src.secret.len() != <KexAlgo::Public as ReprBytes>::Size::USIZE {
            return Err(KeyError::LengthMismatch(
                src.secret.len(),
                <KexAlgo::Public as ReprBytes>::Size::USIZE,
            ));
        }
        Ok(Self {
            secret: GenericArray::from_slice(&src.secret).clone(),
            buffer: GenericArray::from_slice(&src.buffer).clone(),
            counter: src.counter,
        })
    }
}
