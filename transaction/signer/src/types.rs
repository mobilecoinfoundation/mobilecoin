// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializable types for sync between full-service and offline / hardware
//! wallet implementations.

use serde::{Deserialize, Serialize};

use mc_core::keys::{RootSpendPublic, RootViewPrivate, TxOutPublic};
use mc_crypto_ring_signature::KeyImage;

/// View account credentials for sync with full-service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ViewAccount {
    /// Root view private key
    #[serde(with = "pri_key_hex")]
    pub view_private: RootViewPrivate,

    /// Root spend public key
    #[serde(with = "pub_key_hex")]
    pub spend_public: RootSpendPublic,
}

/// Convert a serializable signer [ViewAccount] object to the `mc_core` version
impl From<ViewAccount> for mc_core::account::ViewAccount {
    fn from(v: ViewAccount) -> Self {
        mc_core::account::ViewAccount::new(v.view_private, v.spend_public)
    }
}

/// Convert an `mc_core` [ViewAccount] object to the serializable signer version
impl From<mc_core::account::ViewAccount> for ViewAccount {
    fn from(v: mc_core::account::ViewAccount) -> Self {
        ViewAccount {
            view_private: v.view_private_key().clone(),
            spend_public: v.spend_public_key().clone(),
        }
    }
}

/// Unsynced TxOut instance for resolving key images
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoUnsynced {
    /// Subaddress for unsynced TxOut
    pub subaddress: u64,

    /// tx_out_public_key for unsynced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_out_public_key: TxOutPublic,
}

/// Synced TxOut instance, contains public key and resolved key image for owned
/// TxOuts
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSynced {
    /// tx_out_public_key for synced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_out_public_key: TxOutPublic,

    /// recovered key image for synced TxOut
    #[serde(with = "const_array_hex")]
    pub key_image: KeyImage,
}

/// Public key hex encoding support for serde
pub mod pub_key_hex {
    use mc_core::keys::Key;
    use mc_crypto_keys::RistrettoPublic;
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;

    pub fn serialize<S, ADDR, KIND>(
        t: &Key<ADDR, KIND, RistrettoPublic>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(
        deserializer: D,
    ) -> Result<Key<ADDR, KIND, RistrettoPublic>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32> {})?;

        Key::try_from(&b).map_err(|_e| {
            <D as Deserializer<'de>>::Error::custom("failed to parse ristretto public key")
        })
    }
}

/// Private key hex encoding support for serde
pub mod pri_key_hex {
    use mc_core::keys::Key;
    use mc_crypto_keys::RistrettoPrivate;
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;

    pub fn serialize<S, ADDR, KIND>(
        t: &Key<ADDR, KIND, RistrettoPrivate>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(
        deserializer: D,
    ) -> Result<Key<ADDR, KIND, RistrettoPrivate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32> {})?;

        Key::try_from(&b).map_err(|_e| {
            <D as Deserializer<'de>>::Error::custom("failed to parse ristretto private key")
        })
    }
}

/// Constant array based type hex encoding for serde (use via `#[serde(with =
/// "const_array_hex")]`)
pub mod const_array_hex {
    use super::ConstArrayVisitor;
    use serde::de::{Deserializer, Error};

    pub fn serialize<S: serde::ser::Serializer>(
        t: impl AsRef<[u8]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let s = hex::encode(t.as_ref());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, 'a, D, T, const N: usize>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::de::Deserializer<'de>,
        T: TryFrom<[u8; N]>,
        <T as TryFrom<[u8; N]>>::Error: core::fmt::Display,
    {
        let v = deserializer.deserialize_str(ConstArrayVisitor::<N> {})?;

        T::try_from(v).map_err(|e| <D as Deserializer>::Error::custom(e))
    }
}

/// Serde visitor for hex encoded fixed length byte arrays
pub struct ConstArrayVisitor<const N: usize = 32>;

/// Serde visitor implementation for fixed length arrays of hex-encoded bytes
impl<'de, const N: usize> serde::de::Visitor<'de> for ConstArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(formatter, concat!("A hex encoded array of bytes"))
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        let mut b = [0u8; N];

        hex::decode_to_slice(s, &mut b).map_err(|e| E::custom(e))?;

        Ok(b)
    }
}
