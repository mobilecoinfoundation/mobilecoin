
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Memo HMAC container type
#[derive(Clone, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Hmac(pub [u8; 16]);

impl AsRef<[u8; 16]> for Hmac {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<Hmac> for [u8; 16] {
    fn from(value: Hmac) -> Self {
        value.0
    }
}
