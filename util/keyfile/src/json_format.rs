//! JSON formats for private keys together with fog data.
//! Files formatted in this way are sufficient to derive an account key in
//! a self-contained way without any context, which is useful for many tools.

use core::convert::TryFrom;
use mc_account_keys::{AccountKey, RootEntropy, RootIdentity};
use mc_account_keys_slip10::{Error as AccountKeyError, Slip10Key};
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_util_from_random::FromRandom;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// JSON schema for a slip10 identity
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug, Serialize, Deserialize)]
pub struct Slip10IdentityJson {
    /// Slip10 key
    #[serde(serialize_with = "as_hex", deserialize_with = "from_hex")]
    pub slip10_key: [u8; 32],
    /// User's fog report url, if any.
    pub fog_report_url: String,
    /// User's report id, if any.
    pub fog_report_id: String,
    /// User's fog authority subjectPublicKeyInfo bytes, if any
    pub fog_authority_spki: Vec<u8>,
}

impl Slip10IdentityJson {
    /// Construct an identity without fog and with a random slip10 key
    pub fn random<T: RngCore + CryptoRng>(rng: &mut T) -> Self {
        Self {
            slip10_key: FromRandom::from_random(rng),
            ..Default::default()
        }
    }

    /// Construct an identity with fog and with a random slip10 key
    pub fn random_with_fog<T: RngCore + CryptoRng>(
        rng: &mut T,
        fog_report_url: &str,
        fog_report_id: &str,
        fog_authority_spki: &[u8],
    ) -> Self {
        let mut result = Self::random(rng);

        if !fog_report_url.is_empty() {
            result.fog_report_url = fog_report_url.to_owned();
            result.fog_report_id = fog_report_id.to_owned();
            result.fog_authority_spki = fog_authority_spki.to_owned();
        }

        result
    }
}

impl TryFrom<&Slip10IdentityJson> for AccountKey {
    type Error = AccountKeyError;
    fn try_from(src: &Slip10IdentityJson) -> Result<AccountKey, AccountKeyError> {
        Slip10Key::from(src.slip10_key).try_into_account_key(
            &src.fog_report_url,
            &src.fog_report_id,
            &src.fog_authority_spki,
        )
    }
}

fn as_hex<S>(key: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&key[..]))
}

fn from_hex<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(&string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes| {
            <[u8; 32] as TryFrom<&[u8]>>::try_from(&bytes)
                .map_err(|err| Error::custom(err.to_string()))
        })
}

/// Historical JSON schema for a root identity
#[derive(Clone, PartialEq, Eq, Hash, Default, Debug, Serialize, Deserialize)]
pub struct RootIdentityJson {
    /// Root entropy used to derive a user's private keys.
    pub root_entropy: [u8; 32],
    /// User's fog url, if any.
    pub fog_url: String,
    /// User's report id, if any.
    pub fog_report_id: String,
    /// User's fog authority subjectPublicKeyInfo bytes, if any
    pub fog_authority_spki: Vec<u8>,
}

impl From<&RootIdentity> for RootIdentityJson {
    fn from(src: &RootIdentity) -> Self {
        Self {
            root_entropy: src.root_entropy.bytes,
            fog_url: src.fog_report_url.clone(),
            fog_report_id: src.fog_report_id.clone(),
            fog_authority_spki: src.fog_authority_spki.clone(),
        }
    }
}

impl From<RootIdentityJson> for RootIdentity {
    fn from(src: RootIdentityJson) -> Self {
        Self {
            root_entropy: RootEntropy::from(&src.root_entropy),
            fog_report_url: src.fog_url,
            fog_report_id: src.fog_report_id,
            fog_authority_spki: src.fog_authority_spki,
        }
    }
}
