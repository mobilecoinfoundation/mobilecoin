// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Basic key types

use core::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use zeroize::Zeroize;

use mc_crypto_keys::{KeyError, ReprBytes, RistrettoPrivate, RistrettoPublic};

use crate::markers::*;

// Exported key types

/// Subaddress view private key
pub type SubaddressViewPrivate = Key<Subaddress, View, RistrettoPrivate>;
/// Subaddress spend private key
pub type SubaddressSpendPrivate = Key<Subaddress, Spend, RistrettoPrivate>;

/// Subaddress view public key
pub type SubaddressViewPublic = Key<Subaddress, View, RistrettoPublic>;
/// Subaddress spend public key
pub type SubaddressSpendPublic = Key<Subaddress, Spend, RistrettoPublic>;

/// Root view private key
pub type RootViewPrivate = Key<Root, View, RistrettoPrivate>;
/// Root spend private key
pub type RootSpendPrivate = Key<Root, Spend, RistrettoPrivate>;

/// Root view public key
pub type RootViewPublic = Key<Root, View, RistrettoPublic>;
/// Root spend public key
pub type RootSpendPublic = Key<Root, Spend, RistrettoPublic>;

/// TxOut public key
pub type TxOutPublic = Key<TxOut, Public, RistrettoPublic>;
/// TxOut target public key
pub type TxOutTargetPublic = Key<TxOut, Target, RistrettoPublic>;

/// Generic key object, see type aliases for use
#[derive(Clone, Debug, Zeroize)]
pub struct Key<ADDR, KIND, KEY: Default + Zeroize> {
    /// Key data
    key: KEY,
    /// Address (root, sub, etc.) marker
    #[zeroize(skip)]
    _addr: PhantomData<ADDR>,
    /// Kind (view, spend, etc.) marker
    #[zeroize(skip)]
    _kind: PhantomData<KIND>,
}

/// Explicit conversion to internal key type for backwards compatibility
impl<ADDR, KIND, KEY: Default + Zeroize> Key<ADDR, KIND, KEY> {
    pub fn inner(self) -> KEY {
        self.key
    }
}

/// AsRef to internal key type for backwards compatibility
impl<ADDR, KIND, KEY: Default + Zeroize> AsRef<KEY> for Key<ADDR, KIND, KEY> {
    fn as_ref(&self) -> &KEY {
        &self.key
    }
}

/// Create a default key object
impl<ADDR, KIND, KEY: Default + Zeroize> Default for Key<ADDR, KIND, KEY> {
    fn default() -> Self {
        Self {
            key: KEY::default(),
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// Expose [`ReprBytes`] for internal `KEY` types implementing this
impl<ADDR, KIND, KEY> ReprBytes for Key<ADDR, KIND, KEY>
where
    KEY: ReprBytes + Default + Zeroize,
{
    type Size = <KEY as ReprBytes>::Size;

    type Error = <KEY as ReprBytes>::Error;

    fn from_bytes(src: &mc_crypto_keys::GenericArray<u8, Self::Size>) -> Result<Self, Self::Error> {
        let key = <KEY as ReprBytes>::from_bytes(src)?;
        Ok(Key {
            key,
            _addr: PhantomData,
            _kind: PhantomData,
        })
    }

    fn to_bytes(&self) -> mc_crypto_keys::GenericArray<u8, Self::Size> {
        <KEY as ReprBytes>::to_bytes(&self.key)
    }
}

// Shared public key methods

impl<ADDR, KIND> Key<ADDR, KIND, RistrettoPublic> {
    /// Fetch public key bytes in compressed form
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// Fetch the public key for a private key instance
impl<ADDR, KIND> From<&Key<ADDR, KIND, RistrettoPrivate>> for Key<ADDR, KIND, RistrettoPublic> {
    fn from(p: &Key<ADDR, KIND, RistrettoPrivate>) -> Self {
        Self {
            key: RistrettoPublic::from(&p.key),
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// Create a public key from [`RistrettoPublic`] object
impl<ADDR, KIND> From<RistrettoPublic> for Key<ADDR, KIND, RistrettoPublic> {
    fn from(p: RistrettoPublic) -> Self {
        Self {
            key: p,
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// Attempt to create a public key from a compressed point, wrapping
/// [`RistrettoPublic::try_from`]
impl<ADDR, KIND> TryFrom<&[u8; 32]> for Key<ADDR, KIND, RistrettoPublic> {
    type Error = KeyError;

    fn try_from(p: &[u8; 32]) -> Result<Self, Self::Error> {
        let key = RistrettoPublic::try_from(p)?;
        Ok(Self {
            key,
            _addr: PhantomData,
            _kind: PhantomData,
        })
    }
}

/// Attempt to create a public key from a compressed point, wrapping
/// [`RistrettoPublic::try_from`]
impl<ADDR, KIND> TryFrom<[u8; 32]> for Key<ADDR, KIND, RistrettoPublic> {
    type Error = KeyError;

    fn try_from(p: [u8; 32]) -> Result<Self, Self::Error> {
        Self::try_from(&p)
    }
}

/// Access underlying [`RistrettoPoint`] for public key containers
impl<ADDR, KIND> From<&Key<ADDR, KIND, RistrettoPublic>> for RistrettoPoint {
    fn from(k: &Key<ADDR, KIND, RistrettoPublic>) -> Self {
        *k.key.as_ref()
    }
}

/// PartialEq for public key objects
impl<ADDR, KIND> PartialEq for Key<ADDR, KIND, RistrettoPublic> {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

/// PartialEq for backwards compatibility with public key objects
impl<ADDR, KIND> PartialEq<RistrettoPublic> for Key<ADDR, KIND, RistrettoPublic> {
    fn eq(&self, other: &RistrettoPublic) -> bool {
        &self.key == other
    }
}

/// PartialEq for backwards compatibility with public key objects
impl<ADDR, KIND> PartialEq<Key<ADDR, KIND, RistrettoPublic>> for RistrettoPublic {
    fn eq(&self, other: &Key<ADDR, KIND, RistrettoPublic>) -> bool {
        self == &other.key
    }
}

/// [core::fmt::Display] for public key objects
impl<ADDR, KIND> Display for Key<ADDR, KIND, RistrettoPublic> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data = self.key.to_bytes();
        for d in data {
            write!(f, "{:02x}", d)?;
        }
        Ok(())
    }
}

/// [core::fmt::LowerHex] for public key objects
impl<ADDR, KIND> core::fmt::LowerHex for Key<ADDR, KIND, RistrettoPublic> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data = self.key.to_bytes();
        for d in data {
            write!(f, "{:02x}", d)?;
        }
        Ok(())
    }
}

/// [core::fmt::UpperHex] for public key objects
impl<ADDR, KIND> core::fmt::UpperHex for Key<ADDR, KIND, RistrettoPublic> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let data = self.key.to_bytes();
        for d in data {
            write!(f, "{:02X}", d)?;
        }
        Ok(())
    }
}

// Shared private key methods

impl<ADDR, KIND> Key<ADDR, KIND, RistrettoPrivate> {
    /// Fetch private key bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

/// Create a private key from [`RistrettoPrivate`] object
impl<ADDR, KIND> From<RistrettoPrivate> for Key<ADDR, KIND, RistrettoPrivate> {
    fn from(p: RistrettoPrivate) -> Self {
        Self {
            key: p,
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// Fetch corresponding public key for a private key object
impl<ADDR, KIND> From<Key<ADDR, KIND, RistrettoPrivate>> for Key<ADDR, KIND, RistrettoPublic> {
    fn from(p: Key<ADDR, KIND, RistrettoPrivate>) -> Self {
        Self {
            key: RistrettoPublic::from(&p.key),
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// Attempt to create a private key from a compressed point, wrapping
/// [RistrettoPrivate::try_from]
impl<ADDR, KIND> TryFrom<&[u8; 32]> for Key<ADDR, KIND, RistrettoPrivate> {
    type Error = KeyError;

    fn try_from(p: &[u8; 32]) -> Result<Self, Self::Error> {
        let key = RistrettoPrivate::try_from(p)?;
        Ok(Self {
            key,
            _addr: PhantomData,
            _kind: PhantomData,
        })
    }
}

/// Attempt to create a private key from a compressed point, wrapping
/// [RistrettoPrivate::try_from]
impl<ADDR, KIND> TryFrom<[u8; 32]> for Key<ADDR, KIND, RistrettoPrivate> {
    type Error = KeyError;

    fn try_from(p: [u8; 32]) -> Result<Self, Self::Error> {
        Self::try_from(&p)
    }
}

/// Access underlying [Scalar] for private key objects
impl <ADDR, KIND> From<&Key<ADDR, KIND, RistrettoPrivate>> for Scalar {
    fn from(k: &Key<ADDR, KIND, RistrettoPrivate>) -> Self {
        *k.key.as_ref()
    }
}

/// Create a private key from raw [Scalar]
impl<ADDR, KIND> From<Scalar> for Key<ADDR, KIND, RistrettoPrivate> {
    fn from(s: Scalar) -> Self {
        Self {
            key: RistrettoPrivate::from(s),
            _addr: PhantomData,
            _kind: PhantomData,
        }
    }
}

/// [PartialEq] via public key conversion for Private key objects
impl<ADDR, KIND> PartialEq for Key<ADDR, KIND, RistrettoPrivate> {
    fn eq(&self, other: &Self) -> bool {
        RistrettoPublic::from(&self.key) == RistrettoPublic::from(&other.key)
    }
}

/// [PartialEq] for backwards compatibility with private key objects
impl<ADDR, KIND> PartialEq<RistrettoPrivate> for Key<ADDR, KIND, RistrettoPrivate> {
    fn eq(&self, other: &RistrettoPrivate) -> bool {
        RistrettoPublic::from(&self.key) == RistrettoPublic::from(other)
    }
}

/// [PartialEq] for backwards compatibility with private key objects
impl<ADDR, KIND> PartialEq<Key<ADDR, KIND, RistrettoPrivate>> for RistrettoPrivate {
    fn eq(&self, other: &Key<ADDR, KIND, RistrettoPrivate>) -> bool {
        RistrettoPublic::from(self) == RistrettoPublic::from(&other.key)
    }
}

/// [core::fmt::Display] for private key objects
impl<ADDR, KIND> Display for Key<ADDR, KIND, RistrettoPrivate> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "pub({})", RistrettoPublic::from(&self.key))
    }
}

/// [serde::Serialize] implementation for private key types
#[cfg(feature = "serde")]
impl<ADDR, KIND> serde::ser::Serialize for Key<ADDR, KIND, RistrettoPrivate> {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.key.to_bytes())
    }
}

/// [serde::Serialize] implementation for public key types
#[cfg(feature = "serde")]
impl<ADDR, KIND> serde::ser::Serialize for Key<ADDR, KIND, RistrettoPublic> {
    fn serialize<S: serde::ser::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.key.to_bytes())
    }
}

/// [serde::Deserialize] implementation for all key types
#[cfg(feature = "serde")]
impl<'de, ADDR, KIND, KEY> serde::de::Deserialize<'de> for Key<ADDR, KIND, KEY>
where
    KEY: Default + Zeroize + TryFrom<&'de [u8]>,
    <KEY as TryFrom<&'de [u8]>>::Error: core::fmt::Display,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let key = deserializer.deserialize_bytes(KeyVisitor::<KEY>(PhantomData))?;

        Ok(Self {
            key,
            _addr: PhantomData,
            _kind: PhantomData,
        })
    }
}

/// Serde visitor for [`Key`] types supporting `TryFrom<&[u8]>`
#[cfg(feature = "serde")]
struct KeyVisitor<KEY>(PhantomData<KEY>);

/// Visitor implementation for [Key] types supporting `TryFrom<&[u8]>`
#[cfg(feature = "serde")]
impl<'de, KEY> serde::de::Visitor<'de> for KeyVisitor<KEY>
where
    KEY: TryFrom<&'de [u8]>,
    <KEY as TryFrom<&'de [u8]>>::Error: core::fmt::Display,
{
    type Value = KEY;

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(
            formatter,
            concat!("A ", stringify!(K), " as array of bytes")
        )
    }

    fn visit_borrowed_bytes<E: serde::de::Error>(self, value: &'de [u8]) -> Result<Self::Value, E> {
        match Self::Value::try_from(value) {
            Ok(v) => Ok(v),
            Err(e) => Err(E::custom(e)),
        }
    }
}

/// [Key] implementation of [prost::Message] when its inner `KEY` type implements [prost::Message].
#[cfg(feature = "prost")]
impl<ADDR, KIND, KEY> prost::Message for Key<ADDR, KIND, KEY>
where
    ADDR: Send + Sync + Debug,
    KIND: Send + Sync + Debug,
    KEY: prost::Message + Zeroize + Default + Debug,
{
    fn encode_raw<B>(&self, buf: &mut B)
    where
        B: prost::bytes::BufMut,
        Self: Sized,
    {
        <KEY as prost::Message>::encode_raw(&self.key, buf)
    }

    fn merge_field<B>(
        &mut self,
        tag: u32,
        wire_type: prost::encoding::WireType,
        buf: &mut B,
        ctx: prost::encoding::DecodeContext,
    ) -> Result<(), prost::DecodeError>
    where
        B: prost::bytes::Buf,
        Self: Sized,
    {
        <KEY as prost::Message>::merge_field(&mut self.key, tag, wire_type, buf, ctx)
    }

    fn encoded_len(&self) -> usize {
        <KEY as prost::Message>::encoded_len(&self.key)
    }

    fn clear(&mut self) {
        <KEY as prost::Message>::clear(&mut self.key)
    }
}
