//! Helpers for encoding / decoding core types
//! 

/// Public key hex encoding support for serde
#[cfg(feature = "serde")]
pub mod pub_key_hex {
    use crate::keys::Key;
    use mc_crypto_keys::{RistrettoPublic};
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;


    pub fn serialize<S, ADDR, KIND>(t: &Key<ADDR, KIND, RistrettoPublic>, serializer: S) -> Result<S::Ok, S::Error> 
    where 
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(deserializer: D) -> Result<Key<ADDR, KIND, RistrettoPublic>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32>{})?;

        Key::try_from(&b)
            .map_err(|_e| <D as Deserializer<'de>>::Error::custom("failed to parse ristretto public key"))
    }
}

/// Private key hex encoding support for serde
#[cfg(feature = "serde")]
pub mod pri_key_hex {
    use crate::keys::Key;
    use mc_crypto_keys::{RistrettoPrivate};
    use serde::de::{Deserializer, Error};

    use super::ConstArrayVisitor;


    pub fn serialize<S, ADDR, KIND>(t: &Key<ADDR, KIND, RistrettoPrivate>, serializer: S) -> Result<S::Ok, S::Error> 
    where 
        S: serde::ser::Serializer,
    {
        let s = hex::encode(t.to_bytes());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D, ADDR, KIND>(deserializer: D) -> Result<Key<ADDR, KIND, RistrettoPrivate>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let b = deserializer.deserialize_str(ConstArrayVisitor::<32>{})?;

        Key::try_from(&b)
            .map_err(|_e| <D as Deserializer<'de>>::Error::custom("failed to parse ristretto private key"))
    }
}

/// Constant array based type hex encoding for serde (use via `#[serde(with = "const_array_hex")]`)
pub mod const_array_hex {
    use serde::de::{Deserializer, Error};
    use super::ConstArrayVisitor;

    pub fn serialize<S: serde::ser::Serializer>(t: impl AsRef<[u8]>, serializer: S) -> Result<S::Ok, S::Error> {
        let s = hex::encode(t.as_ref());
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, 'a, D, T, const N: usize>(deserializer: D) -> Result<T, D::Error>
    where
        D: serde::de::Deserializer<'de>,
        T: TryFrom<[u8; N]>,
        <T as TryFrom<[u8; N]>>::Error: core::fmt::Display,
    {
        let v = deserializer.deserialize_str(ConstArrayVisitor::<N>{})?;

        T::try_from(v)
            .map_err(|e| <D as Deserializer>::Error::custom(e))
    }
}


/// Serde visitor for hex encoded fixed length byte arrays
#[cfg(feature = "serde")]
pub struct ConstArrayVisitor<const N: usize = 32>;

/// Serde visitor implementation for fixed length arrays of hex-encoded bytes
#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::de::Visitor<'de> for ConstArrayVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        write!(
            formatter,
            concat!("A hex encoded array of bytes")
        )
    }

    fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
        let mut b = [0u8; N];

        hex::decode_to_slice(s, &mut b)
            .map_err(|e| E::custom(e))?;

        Ok(b)
    }
}
