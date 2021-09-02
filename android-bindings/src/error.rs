// Copyright (c) 2018-2021 The MobileCoin Foundation

use bip39::ErrorKind as Bip39Error;
use displaydoc::Display;
use mc_attest_ake::Error as AkeError;
use mc_attest_core::VerifyError as AttestVerifyError;
use mc_crypto_box::Error as CryptoBoxError;
use mc_crypto_keys::KeyError;
use mc_crypto_noise::CipherError;
use mc_fog_kex_rng::Error as KexRngError;
use mc_transaction_core::{ring_signature::Error as RingSignatureError, AmountError};
use mc_transaction_std::TxBuilderError;
use mc_util_encodings::Error as EncodingsError;
use mc_util_serial::{
    decode::Error as DeserializeError, encode::Error as SerializeError, DecodeError, EncodeError,
};
use mc_util_uri::{UriConversionError, UriParseError};
use std::{array::TryFromSliceError, str::Utf8Error, string::FromUtf8Error};

#[derive(Debug, Display)]
pub enum McError {
    /// FromUtf8Error: {0}
    FromUtf8(FromUtf8Error),

    /// TryFromSlice: {0}
    TryFromSlice(TryFromSliceError),

    /// KeyError: {0}
    Key(KeyError),

    /// RingSignature: {0}
    RingSignature(RingSignatureError),

    /// AmountError: {0}
    Amount(AmountError),

    /// Utf8Error: {0}
    Utf8(Utf8Error),

    /// UriParseError: {0}
    UriParse(UriParseError),

    /// UriConversionError: {0}
    UriConversion(UriConversionError),

    /// AkeError: {0}
    Ake(AkeError),

    /// CipherError: {0}
    Cipher(CipherError),

    /// EncodeError: {0}
    Encode(EncodeError),

    /// DecodeError: {0}
    Decode(DecodeError),

    /// SerializeError: {0}
    Serialize(SerializeError),

    /// DeserializeError: {0}
    Deserialize(DeserializeError),

    /// TxBuilderError: {0}
    TxBuilder(TxBuilderError),

    /// CryptoBoxError: {0}
    CryptoBox(CryptoBoxError),

    /// KexRngError: {0}
    KexRng(KexRngError),

    /// AttestVerifyError: {0}
    AttestVerify(AttestVerifyError),

    /// EncodingsError: {0}
    Encodings(EncodingsError),

    /// Panic: {0}
    Panic(String),

    /// Other: {0}
    Other(String),

    /// Jni: {0}
    Jni(String),

    /// Bip39: {0}
    Bip39(Bip39Error),

    /// Downcast from Anyhow Error failed: {0}
    DowncastAnyFailed(anyhow::Error),
}

impl From<FromUtf8Error> for McError {
    fn from(src: FromUtf8Error) -> Self {
        Self::FromUtf8(src)
    }
}

impl From<TryFromSliceError> for McError {
    fn from(src: TryFromSliceError) -> Self {
        Self::TryFromSlice(src)
    }
}

impl From<KeyError> for McError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<RingSignatureError> for McError {
    fn from(src: RingSignatureError) -> Self {
        Self::RingSignature(src)
    }
}

impl From<AmountError> for McError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}

impl From<Utf8Error> for McError {
    fn from(src: Utf8Error) -> Self {
        Self::Utf8(src)
    }
}

impl From<UriParseError> for McError {
    fn from(src: UriParseError) -> Self {
        Self::UriParse(src)
    }
}

impl From<UriConversionError> for McError {
    fn from(src: UriConversionError) -> Self {
        Self::UriConversion(src)
    }
}

impl From<AkeError> for McError {
    fn from(src: AkeError) -> Self {
        Self::Ake(src)
    }
}

impl From<CipherError> for McError {
    fn from(src: CipherError) -> Self {
        Self::Cipher(src)
    }
}

impl From<EncodeError> for McError {
    fn from(src: EncodeError) -> Self {
        Self::Encode(src)
    }
}

impl From<DecodeError> for McError {
    fn from(src: DecodeError) -> Self {
        Self::Decode(src)
    }
}

impl From<SerializeError> for McError {
    fn from(src: SerializeError) -> Self {
        Self::Serialize(src)
    }
}

impl From<DeserializeError> for McError {
    fn from(src: DeserializeError) -> Self {
        Self::Deserialize(src)
    }
}

impl From<TxBuilderError> for McError {
    fn from(src: TxBuilderError) -> Self {
        Self::TxBuilder(src)
    }
}

impl From<CryptoBoxError> for McError {
    fn from(src: CryptoBoxError) -> Self {
        Self::CryptoBox(src)
    }
}

impl From<KexRngError> for McError {
    fn from(src: KexRngError) -> Self {
        Self::KexRng(src)
    }
}

impl From<AttestVerifyError> for McError {
    fn from(src: AttestVerifyError) -> Self {
        Self::AttestVerify(src)
    }
}

impl From<EncodingsError> for McError {
    fn from(src: EncodingsError) -> Self {
        Self::Encodings(src)
    }
}

impl From<jni::errors::Error> for McError {
    fn from(src: jni::errors::Error) -> Self {
        Self::Jni(src.to_string())
    }
}

impl From<anyhow::Error> for McError {
    fn from(src: anyhow::Error) -> Self {
        match src.downcast::<Bip39Error>() {
            Ok(error_kind) => error_kind.into(),
            Err(e) => Self::DowncastAnyFailed(e),
        }
    }
}

impl From<Bip39Error> for McError {
    fn from(src: Bip39Error) -> Self {
        Self::Bip39(src)
    }
}
