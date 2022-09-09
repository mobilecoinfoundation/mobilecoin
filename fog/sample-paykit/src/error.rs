// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin SDK Errors

use displaydoc::Display;
use mc_connection::Error as ConnectionError;
use mc_consensus_api::ConversionError;
use mc_crypto_keys::KeyError;
use mc_fog_enclave_connection::Error as EnclaveConnectionError;
use mc_fog_ledger_connection::{Error as LedgerConnectionError, KeyImageQueryError};
use mc_fog_report_connection::Error as FogResolutionError;
use mc_fog_types::view::FogTxOutError;
use mc_fog_view_protocol::TxOutPollingError;
use mc_transaction_core::{
    validation::TransactionValidationError, AmountError, BlockVersionError,
    SignedContingentInputError, TxOutConversionError,
};
use mc_transaction_std::{SignedContingentInputBuilderError, TxBuilderError};
use mc_util_uri::UriParseError;
use std::result::Result as StdResult;

/// A result type alias for the sample paykit
pub type Result<T> = StdResult<T, Error>;

type FogViewError = TxOutPollingError<EnclaveConnectionError>;

/// An error that can occur when trying to match a TxOut against our view key
#[derive(Debug, Display)]
pub enum TxOutMatchingError {
    /// Amount Error (could not decode the amount): {0}
    Amount(AmountError),

    /// Error parsing key: {0}
    Key(KeyError),

    /// TxOut conversion error: {0}
    TxOutConversion(TxOutConversionError),

    /// Error decompressing FogTxOut: {0}
    FogTxOut(FogTxOutError),

    /// Subaddress not found
    SubaddressNotFound,
}

impl From<AmountError> for TxOutMatchingError {
    fn from(src: AmountError) -> Self {
        Self::Amount(src)
    }
}

impl From<KeyError> for TxOutMatchingError {
    fn from(src: KeyError) -> Self {
        Self::Key(src)
    }
}

impl From<FogTxOutError> for TxOutMatchingError {
    fn from(src: FogTxOutError) -> Self {
        Self::FogTxOut(src)
    }
}

impl From<TxOutConversionError> for TxOutMatchingError {
    fn from(src: TxOutConversionError) -> Self {
        Self::TxOutConversion(src)
    }
}

/// An error that can be returned by the sample paykit
#[derive(Debug, Display)]
pub enum Error {
    /// Error in connection to consensus: {0}
    ConsensusConnection(ConnectionError),

    /// Missing or extra rings ({0}) for inputs ({1})
    RingsForInput(usize, usize),

    /// Ring contains {0} items, real key at position {1}
    BrokenRing(usize, usize),

    /// Insufficient TxOuts in blockchain: Needed {0}, found {1}
    InsufficientTxOutsInBlockchain(usize, usize),

    /// Error adding tx outputs: {0}
    AddOutput(TxBuilderError),

    /// Error finalizing transaction: {0}
    BuildTx(TxBuilderError),

    /// Error parsing key: {0}
    Key(KeyError),

    /// Insufficient funds available or given
    InsufficientFunds,

    /// Wallet Compacting needed, recommended self-payment amount: {0}
    WalletCompactingNeeded(u64),

    /// Error communicating with ledger server: {0}
    LedgerConnection(LedgerConnectionError),

    /// The ledger server could not handle a key image query: {0}
    KeyImageQuery(KeyImageQueryError),

    /// The ledger server returned an unexpected block range: {0}-{1}
    UnexpectedBlockRange(u64, u64),

    /// The untrusted tx out server returned an error: {0}
    UntrustedTxOut(LedgerConnectionError),

    /// Error recovering Txos from fog: {0}
    TxRecovery(FogViewError),

    /// Could not obtain fog service public key: {0}
    FogResolution(FogResolutionError),

    /// Failed to decode ledger server response: {0}
    Conversion(ConversionError),

    /// Proposed transcation rejected: {0}
    TxRejected(TransactionValidationError),

    /// Could not parse uri: {0}
    Uri(UriParseError),

    /// Block version error: {0}
    BlockVersion(BlockVersionError),

    /// Signed contingent input is unprofitable
    SciUnprofitable,

    /// Signed contingent input is expired
    SciExpired,

    /// SCI's tx out index ({0}) didn't match to the claimed tx out
    SciGlobalIndexTxOutMismatch(u64),

    /// Signed Contingent Input: {0}
    SignedContingentInput(SignedContingentInputError),

    /// Signed Contingent Input Builder: {0}
    SignedContingentInputBuilder(SignedContingentInputBuilderError),

    /// Fog merkle proof: {0}
    FogMerkleProof(String),
}

impl From<ConnectionError> for Error {
    fn from(x: ConnectionError) -> Error {
        match x {
            ConnectionError::TransactionValidation(tve) => Error::TxRejected(tve),
            other => Error::ConsensusConnection(other),
        }
    }
}

impl From<ConversionError> for Error {
    fn from(x: ConversionError) -> Error {
        Error::Conversion(x)
    }
}

impl From<KeyError> for Error {
    fn from(x: KeyError) -> Error {
        Error::Key(x)
    }
}

impl From<LedgerConnectionError> for Error {
    fn from(x: LedgerConnectionError) -> Error {
        Error::LedgerConnection(x)
    }
}

impl From<KeyImageQueryError> for Error {
    fn from(x: KeyImageQueryError) -> Error {
        Error::KeyImageQuery(x)
    }
}

impl From<TransactionValidationError> for Error {
    fn from(x: TransactionValidationError) -> Error {
        Error::TxRejected(x)
    }
}

impl From<TxBuilderError> for Error {
    fn from(x: TxBuilderError) -> Error {
        Error::BuildTx(x)
    }
}

impl From<SignedContingentInputBuilderError> for Error {
    fn from(x: SignedContingentInputBuilderError) -> Error {
        Error::SignedContingentInputBuilder(x)
    }
}

impl From<SignedContingentInputError> for Error {
    fn from(x: SignedContingentInputError) -> Error {
        Error::SignedContingentInput(x)
    }
}

impl From<FogViewError> for Error {
    fn from(x: FogViewError) -> Error {
        Error::TxRecovery(x)
    }
}

impl From<FogResolutionError> for Error {
    fn from(x: FogResolutionError) -> Error {
        Error::FogResolution(x)
    }
}

impl From<UriParseError> for Error {
    fn from(src: UriParseError) -> Self {
        Self::Uri(src)
    }
}

impl From<BlockVersionError> for Error {
    fn from(src: BlockVersionError) -> Self {
        Self::BlockVersion(src)
    }
}
