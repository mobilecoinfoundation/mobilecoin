// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Serializable types for exchange between full-service and offline or hardware
//! wallet implementations.

use mc_core::{
    keys::{RootSpendPublic, RootViewPrivate, TxOutPublic},
};

use mc_crypto_ring_signature::KeyImage;
use mc_transaction_core::{
    ring_ct::{InputRing, OutputSecret},
    tx::{Tx, TxPrefix},
    BlockVersion,
};
use mc_transaction_extra::TxOutSummaryUnblindingData;
use serde::{Deserialize, Serialize};

/// View account credentials produced by a signer implementation
/// for import by full-service
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    /// Root view private key
    #[serde(with = "pri_key_hex")]
    pub view_private: RootViewPrivate,

    /// Root spend public key
    #[serde(with = "pub_key_hex")]
    pub spend_public: RootSpendPublic,

    /// SLIP-0010 account index used for key derivation
    pub account_index: u32,
}

/// Convert a serializable signer [ViewAccount] object to the `mc_core` version
impl From<AccountInfo> for mc_core::account::ViewAccount {
    fn from(v: AccountInfo) -> Self {
        mc_core::account::ViewAccount::new(v.view_private, v.spend_public)
    }
}

/// Request to sync TxOuts for the provided account, issued by full-service
/// to support key image scanning.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSyncReq {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// TxOut subaddress and public key pairs to be synced
    pub txos: Vec<TxoUnsynced>,
}

/// Unsynced TxOut subaddress and public key pair for resolving key images
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoUnsynced {
    /// Subaddress for unsynced TxOut
    pub subaddress: u64,

    /// tx_out_public_key for unsynced TxOut
    #[serde(with = "pub_key_hex")]
    pub tx_out_public_key: TxOutPublic,
}

/// Synced TxOut response, returned to full-service in response to a
/// [TxoSyncReq] to support key image scanning
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxoSyncResp {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// public keys and key images for synced TxOuts
    pub txos: Vec<TxoSynced>,
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

/// Transaction signing request, issued by full-service to a signer
/// implementation for signing
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxSignReq {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// The fully constructed TxPrefix.
    pub tx_prefix: TxPrefix,

    /// rings
    pub rings: Vec<InputRing>,

    /// Output secrets
    #[serde(flatten)]
    pub secrets: TxSignSecrets,

    /// Block version
    // NOTE: this is superflous
    pub block_version: BlockVersion,
}

/// Transaction signing secrets, either output secrets or unblinding data
/// depending on the block version. Note that transaction summary / verification
/// requires the `TxOutUnblindingData` variant.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub enum TxSignSecrets {
    #[serde(rename = "output_secrets")]
    OutputSecrets(Vec<OutputSecret>),

    // NOTE: this is only the tx outs because you can recover the ins from the unsigned rings
    #[serde(rename = "tx_out_unblinding_data")]
    TxOutUnblindingData(Vec<TxOutSummaryUnblindingData>),
}

impl TxSignReq {
    /// Fetch or convert unblinding data to output secrets
    pub fn output_secrets(&self) -> Vec<OutputSecret> {
        match &self.secrets {
            TxSignSecrets::OutputSecrets(s) => s.clone(),
            TxSignSecrets::TxOutUnblindingData(u) => u
                .iter()
                .map(|data| OutputSecret::from(data.unmasked_amount.clone()))
                .collect(),
        }
    }
}

/// Transaction signing response, returned to full service by the signer
/// implementation following a successful transaction signing.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct TxSignResp {
    /// MOB AccountId for account matching
    #[serde(with = "const_array_hex")]
    pub account_id: AccountId,

    /// Signed transaction
    pub tx: Tx,

    /// Mapping of real Tx public keys to key images
    pub txos: Vec<TxoSynced>,
}


/// Account ID object, derived from an [AccountKey] and used to identify
/// individual accounts.
#[derive(Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AccountId([u8; 32]);

/// Display [AccountId] as a hex encoded string
impl core::fmt::Display for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for v in self.0 {
            write!(f, "{v:02X}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for AccountId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AccountId(")?;
        for v in self.0 {
            write!(f, "{v:02X}")?;
        }
        write!(f, ")")
    }
}

/// Access raw [AccountId] hash
impl AsRef<[u8; 32]> for AccountId {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Create [AccountId] object from raw hash
impl From<[u8; 32]> for AccountId {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Create [AccountId] object from raw hash
impl From<&[u8; 32]> for AccountId {
    fn from(value: &[u8; 32]) -> Self {
        Self(*value)
    }
}

/// Public key hex encoding support for serde
pub(crate) mod pub_key_hex {
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
pub(crate) mod pri_key_hex {
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
pub(crate) mod const_array_hex {
    use super::ConstArrayVisitor;
    use serde::de::{Deserializer, Error};

    pub fn serialize<S: serde::ser::Serializer, const N: usize>(
        t: impl AsRef<[u8; N]>,
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

        T::try_from(v).map_err(<D as Deserializer>::Error::custom)
    }
}

/// Serde visitor for hex encoded fixed length byte arrays
pub(crate) struct ConstArrayVisitor<const N: usize = 32>;

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

/// Serde visitor for hex encoded variable length byte arrays
pub(crate) struct VarArrayVisitor;

/// Serde visitor implementation for variable length arrays of hex-encoded
/// protobufs
impl<'de> serde::de::Visitor<'de> for VarArrayVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(formatter, concat!("A hex encoded array of bytes"))
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        let b = hex::decode(s).map_err(|e| E::custom(e))?;

        Ok(b)
    }
}
