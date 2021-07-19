use crate::{
    aead::{
        generic_array::{
            sequence::{Concat, Split},
            typenum::{Sum, Unsigned},
            ArrayLength, GenericArray,
        },
        AeadInPlace, Error as AeadError, NewAead,
    },
    traits::{CryptoBox, Error},
};

use core::{
    convert::TryFrom,
    marker::PhantomData,
    ops::{Add, Sub},
};
use digest::{BlockInput, Digest, FixedOutput, Reset, Update};
use hkdf::Hkdf;
use mc_crypto_keys::{Kex, ReprBytes};
use mc_oblivious_aes_gcm::{CtAeadDecrypt, CtDecryptResult};
use rand_core::{CryptoRng, RngCore};

/// Represents a generic implementation of CryptoBox using Hkdf, a KexAlgo, and
/// an Aead.
///
/// This structure contains the actual cryptographic primitive details, and
/// specifies part of the wire format of the "footer" where the ephemeral
/// public key comes first, and the mac comes second.
///
/// Preconditions:
/// - Only stateless AEAD is supported. The build will fail if you only have
///   AeadMut.
pub struct HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Update + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: AeadInPlace + NewAead + CtAeadDecrypt,
{
    _kex: PhantomData<fn() -> KexAlgo>,
    _digest: PhantomData<fn() -> DigestAlgo>,
    _aead: PhantomData<fn() -> AeadAlgo>,
}

impl<KexAlgo, DigestAlgo, AeadAlgo> CryptoBox<KexAlgo> for HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Update + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: AeadInPlace + NewAead + CtAeadDecrypt,
    // Note: I think all of these bounds should go away after RFC 2089 is implemented
    // https://github.com/rust-lang/rfcs/blob/master/text/2089-implied-bounds.md
    <<KexAlgo as Kex>::Public as ReprBytes>::Size:
        ArrayLength<u8> + Unsigned + Add<AeadAlgo::TagSize>,
    Sum<<KexAlgo::Public as ReprBytes>::Size, AeadAlgo::TagSize>: ArrayLength<u8>,
    GenericArray<u8, <<KexAlgo as Kex>::Public as ReprBytes>::Size>: Concat<
        u8,
        AeadAlgo::TagSize,
        Rest = GenericArray<u8, AeadAlgo::TagSize>,
        Output = GenericArray<
            u8,
            <<<KexAlgo as Kex>::Public as ReprBytes>::Size as Add<AeadAlgo::TagSize>>::Output,
        >,
    >,
    AeadAlgo::KeySize: Add<AeadAlgo::NonceSize>,
    Sum<AeadAlgo::KeySize, AeadAlgo::NonceSize>:
        ArrayLength<u8> + Sub<AeadAlgo::KeySize, Output = AeadAlgo::NonceSize>,
{
    type FooterSize = Sum<<KexAlgo::Public as ReprBytes>::Size, AeadAlgo::TagSize>;

    fn encrypt_in_place_detached<T: RngCore + CryptoRng>(
        &self,
        rng: &mut T,
        key: &KexAlgo::Public,
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::FooterSize>, AeadError> {
        // ECDH
        use mc_crypto_keys::KexPublic;
        let (our_public, shared_secret) = key.new_secret(rng);

        let curve_point_bytes = our_public.to_bytes();

        // KDF
        let (aes_key, aes_nonce) = Self::kdf_step(&shared_secret);

        // AES
        let aead = AeadAlgo::new(&aes_key);
        let mac = aead.encrypt_in_place_detached(&aes_nonce, &[], buffer)?;

        // Tag is curve_point_bytes || aes_mac_bytes
        Ok(curve_point_bytes.concat(mac))
    }

    fn decrypt_in_place_detached(
        &self,
        key: &KexAlgo::Private,
        tag: &GenericArray<u8, Self::FooterSize>,
        buffer: &mut [u8],
    ) -> Result<CtDecryptResult, Error> {
        // ECDH
        use mc_crypto_keys::KexReusablePrivate;
        // TODO: In generic_array 0.14 the tag can be split without copying it
        let public_key =
            KexAlgo::Public::try_from(&tag[..<KexAlgo::Public as ReprBytes>::Size::USIZE])
                .map_err(Error::Key)?;
        let shared_secret = key.key_exchange(&public_key);

        // KDF
        let (aes_key, aes_nonce) = Self::kdf_step(&shared_secret);

        // AES
        let mac_ref = <&GenericArray<u8, AeadAlgo::TagSize>>::from(
            &tag[<KexAlgo::Public as ReprBytes>::Size::USIZE..],
        );
        let aead = AeadAlgo::new(&aes_key);
        Ok(aead.ct_decrypt_in_place_detached(&aes_nonce, &[], buffer, mac_ref))
    }
}

impl<KexAlgo, DigestAlgo, AeadAlgo> HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Update + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: AeadInPlace + NewAead + CtAeadDecrypt,
    AeadAlgo::KeySize: Add<AeadAlgo::NonceSize>,
    Sum<AeadAlgo::KeySize, AeadAlgo::NonceSize>:
        ArrayLength<u8> + Sub<AeadAlgo::KeySize, Output = AeadAlgo::NonceSize>,
{
    /// KDF part, factored out to avoid duplication
    /// This part must produce the key and IV/nonce for Aead, from the IKM,
    /// using Hkdf.
    fn kdf_step(
        dh_secret: &KexAlgo::Secret,
    ) -> (
        GenericArray<u8, AeadAlgo::KeySize>,
        GenericArray<u8, AeadAlgo::NonceSize>,
    ) {
        let kdf = Hkdf::<DigestAlgo>::new(Some(b"dei-salty-box"), dh_secret.as_ref());
        let mut okm = GenericArray::<u8, Sum<AeadAlgo::KeySize, AeadAlgo::NonceSize>>::default();
        kdf.expand(b"aead-key-iv", okm.as_mut_slice())
            .expect("Digest output size is insufficient");

        let (key, nonce) = Split::<u8, AeadAlgo::KeySize>::split(okm);
        (key, nonce)
    }
}

impl<KexAlgo, DigestAlgo, AeadAlgo> Default for HkdfBox<KexAlgo, DigestAlgo, AeadAlgo>
where
    KexAlgo: Kex,
    for<'privkey> <KexAlgo as Kex>::Public: From<&'privkey <KexAlgo as Kex>::EphemeralPrivate>,
    DigestAlgo: Digest + Update + FixedOutput + Default + Clone + BlockInput + Reset,
    AeadAlgo: AeadInPlace + NewAead + CtAeadDecrypt,
{
    fn default() -> Self {
        Self {
            _kex: Default::default(),
            _digest: Default::default(),
            _aead: Default::default(),
        }
    }
}
