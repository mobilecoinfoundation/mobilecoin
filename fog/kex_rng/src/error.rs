// Copyright (c) 2018-2021 The MobileCoin Foundation

use displaydoc::Display;
use mc_crypto_keys::KeyError;

/// An error that can occur when performing key exchange against KexRngPubkey
#[derive(Clone, Debug, Display)]
pub enum Error {
    /// Error parsing key: {0}
    Key(KeyError),
    /// Unknown KexRng Version: {0}
    UnknownVersion(u32),
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}
