// Copyright (c) 2018-2022 The MobileCoin Foundation

use displaydoc::Display;
use mc_crypto_keys::KeyError;
use mc_transaction_types::{amount::AmountError, BlockVersionError};
use mc_util_zip_exact::ZipExactError;

/// An error which can occur when verifying a TxSummary against unblinding data
#[derive(Clone, Debug, Display)]
pub enum Error {
    /// Unexpected Output
    UnexpectedOutput,
    /// Unexpected Input
    UnexpectedInput,
    /// Still expecting more outputs
    StillExpectingMoreOutputs,
    /// Still expecting more inputs
    StillExpectingMoreInputs,
    /// Amount verification failed
    AmountVerificationFailed,
    /// Address verification failed
    AddressVerificationFailed,
    /// Missing Tx private key
    MissingTxPrivateKey,
    /// Missing data required to verify TxOut recipient
    MissingDataRequiredToVerifyTxOutRecipient,
    /// Numeric overflow
    NumericOverflow,
    /// Buffer overflow
    BufferOverflow,
    /// Block version
    BlockVersion(BlockVersionError),
    /// Missing masked amount
    MissingMaskedAmount,
    /// Key error: {0}
    Key(KeyError),
    /// Amount error: {0}
    Amount(AmountError),
    /// ZipExact error: {0}
    ZipExact(ZipExactError),
}

impl From<BlockVersionError> for Error {
    fn from(src: BlockVersionError) -> Error {
        Error::BlockVersion(src)
    }
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Error {
        Error::Key(src)
    }
}

impl From<AmountError> for Error {
    fn from(src: AmountError) -> Error {
        Error::Amount(src)
    }
}

impl From<ZipExactError> for Error {
    fn from(src: ZipExactError) -> Error {
        Error::ZipExact(src)
    }
}
