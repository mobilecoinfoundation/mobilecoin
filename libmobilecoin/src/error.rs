// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::common::McError;
use displaydoc::Display;
use mc_api::display::Error as ApiDisplayError;
use mc_attest_ake::Error as AttestAkeError;
use mc_attest_core::VerifierError;
use mc_crypto_box::{AeadError, Error as CryptoBoxError};
use mc_crypto_noise::CipherError;
use mc_fog_kex_rng::Error as FogKexRngError;
use mc_fog_report_validation::{ingest_report::Error as IngestReportError, FogPubkeyError};
use mc_transaction_core::AmountError;
use mc_transaction_std::TxBuilderError;
use mc_util_serial::DecodeError;
use protobuf::ProtobufError;
use std::os::raw::c_int;

impl From<LibMcError> for McError {
    fn from(err: LibMcError) -> Self {
        Self::new(err.error_code(), err.error_description())
    }
}

#[derive(Debug, Display)]
pub enum LibMcError {
    /// Unknown
    Unknown,
    /// Rust panicked: {0}
    Panic(String),

    /// Invalid input: {0}
    InvalidInput(String),
    /// Invalid output: {0}
    InvalidOutput(String),

    /// Attestation verification failed: {0}
    AttestationVerificationFailed(String),

    /// Authenticated encryption failure: {0}
    Aead(String),
    /// Cipher error: {0}
    Cipher(String),
    /// Unsupported CryptoBox version: {0}
    UnsupportedCryptoBoxVersion(String),

    /// Transaction cryptography error: {0}
    TransactionCrypto(String),
}

mod error_codes {
    use super::*;

    pub const LIB_MC_ERROR_CODE_UNKNOWN: c_int = -1;
    pub const LIB_MC_ERROR_CODE_PANIC: c_int = -2;

    pub const LIB_MC_ERROR_CODE_INVALID_INPUT: c_int = 100;
    pub const LIB_MC_ERROR_CODE_INVALID_OUTPUT: c_int = 101;

    pub const LIB_MC_ERROR_CODE_ATTESTATION_VERIFICATION_FAILED: c_int = 200;

    pub const LIB_MC_ERROR_CODE_AEAD: c_int = 300;
    pub const LIB_MC_ERROR_CODE_CIPHER: c_int = 301;
    pub const LIB_MC_ERROR_CODE_UNSUPPORTED_CRYPTO_BOX_VERSION: c_int = 302;

    pub const LIB_MC_ERROR_CODE_TRANSACTION_CRYPTO: c_int = 400;
}

impl LibMcError {
    fn error_code(&self) -> c_int {
        use error_codes::*;
        match self {
            LibMcError::Unknown => LIB_MC_ERROR_CODE_UNKNOWN,
            LibMcError::Panic(_) => LIB_MC_ERROR_CODE_PANIC,
            LibMcError::InvalidInput(_) => LIB_MC_ERROR_CODE_INVALID_INPUT,
            LibMcError::InvalidOutput(_) => LIB_MC_ERROR_CODE_INVALID_OUTPUT,
            LibMcError::AttestationVerificationFailed(_) => {
                LIB_MC_ERROR_CODE_ATTESTATION_VERIFICATION_FAILED
            }
            LibMcError::Aead(_) => LIB_MC_ERROR_CODE_AEAD,
            LibMcError::Cipher(_) => LIB_MC_ERROR_CODE_CIPHER,
            LibMcError::UnsupportedCryptoBoxVersion(_) => {
                LIB_MC_ERROR_CODE_UNSUPPORTED_CRYPTO_BOX_VERSION
            }
            LibMcError::TransactionCrypto(_) => LIB_MC_ERROR_CODE_TRANSACTION_CRYPTO,
        }
    }

    fn error_description(&self) -> String {
        format!("{}", self)
    }
}

impl From<AeadError> for LibMcError {
    fn from(err: AeadError) -> Self {
        LibMcError::Aead(format!("{:?}", err))
    }
}

impl From<AmountError> for LibMcError {
    fn from(err: AmountError) -> Self {
        LibMcError::TransactionCrypto(format!("{:?}", err))
    }
}

impl From<ApiDisplayError> for LibMcError {
    fn from(err: ApiDisplayError) -> Self {
        LibMcError::InvalidInput(format!("{:?}", err))
    }
}

impl From<AttestAkeError> for LibMcError {
    fn from(err: AttestAkeError) -> Self {
        if let AttestAkeError::ReportVerification(VerifierError::Verification(_)) = err {
            LibMcError::AttestationVerificationFailed(format!("{:?}", err))
        } else {
            LibMcError::InvalidInput(format!("{:?}", err))
        }
    }
}

impl From<CipherError> for LibMcError {
    fn from(err: CipherError) -> Self {
        if let CipherError::Aead = err {
            LibMcError::Aead(format!("{:?}", err))
        } else {
            LibMcError::Cipher(format!("{:?}", err))
        }
    }
}

impl From<CryptoBoxError> for LibMcError {
    fn from(err: CryptoBoxError) -> Self {
        if let CryptoBoxError::WrongMagicBytes | CryptoBoxError::UnknownAlgorithm(_) = err {
            LibMcError::UnsupportedCryptoBoxVersion(format!("{:?}", err))
        } else {
            LibMcError::InvalidInput(format!("{:?}", err))
        }
    }
}

impl From<DecodeError> for LibMcError {
    fn from(err: DecodeError) -> Self {
        LibMcError::InvalidInput(format!("{:?}", err))
    }
}

impl From<FogKexRngError> for LibMcError {
    fn from(err: FogKexRngError) -> Self {
        if let FogKexRngError::UnknownVersion(_) = err {
            LibMcError::UnsupportedCryptoBoxVersion(format!("{:?}", err))
        } else {
            LibMcError::InvalidInput(format!("{:?}", err))
        }
    }
}

impl From<ProtobufError> for LibMcError {
    fn from(err: ProtobufError) -> Self {
        LibMcError::InvalidInput(format!("{:?}", err))
    }
}

impl From<TxBuilderError> for LibMcError {
    fn from(err: TxBuilderError) -> Self {
        if let TxBuilderError::FogPublicKey(FogPubkeyError::IngestReport(
            IngestReportError::Verifier(VerifierError::Verification(_)),
        )) = err
        {
            LibMcError::AttestationVerificationFailed(format!("{:?}", err))
        } else {
            LibMcError::InvalidInput(format!("{:?}", err))
        }
    }
}
