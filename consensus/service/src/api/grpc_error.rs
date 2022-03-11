// Copyright (c) 2018-2021 The MobileCoin Foundation

use crate::{mint_tx_manager::MintTxManagerError, tx_manager::TxManagerError};
use displaydoc::Display;
use grpcio::{RpcStatus, RpcStatusCode};
use mc_common::logger::global_log;
use mc_consensus_api::{
    consensus_client::{MintValidationResult, ProposeMintConfigTxResponse},
    consensus_common::{ProposeTxResponse, ProposeTxResult},
};
use mc_consensus_enclave::Error as EnclaveError;
use mc_ledger_db::Error as LedgerError;
use mc_transaction_core::{mint::MintValidationError, validation::TransactionValidationError};

#[derive(Debug, Display)]
pub enum ConsensusGrpcError {
    /// GRPC Error: `{0:?}`
    RpcStatus(RpcStatus),

    /// Ledger error: `{0}`
    Ledger(LedgerError),

    /// Service is over capacity
    OverCapacity,

    /// Service is currently not serving requests
    NotServing,

    /// Enclave error: `{0}`
    Enclave(EnclaveError),

    /// Transaction validation error `{0}`
    TransactionValidation(TransactionValidationError),

    /// Mint transaction validation error `{0}`
    MintValidation(MintValidationError),

    /// Invalid argument `{0}`
    InvalidArgument(String),

    /// Other error `{0}`
    Other(String),
}

impl From<RpcStatus> for ConsensusGrpcError {
    fn from(src: RpcStatus) -> Self {
        Self::RpcStatus(src)
    }
}

impl From<LedgerError> for ConsensusGrpcError {
    fn from(src: LedgerError) -> Self {
        Self::Ledger(src)
    }
}

impl From<EnclaveError> for ConsensusGrpcError {
    fn from(src: EnclaveError) -> Self {
        match src {
            EnclaveError::MalformedTx(err) => Self::from(err),
            _ => Self::Enclave(src),
        }
    }
}

impl From<TransactionValidationError> for ConsensusGrpcError {
    fn from(src: TransactionValidationError) -> Self {
        Self::TransactionValidation(src)
    }
}

impl From<MintValidationError> for ConsensusGrpcError {
    fn from(src: MintValidationError) -> Self {
        Self::MintValidation(src)
    }
}

impl From<TxManagerError> for ConsensusGrpcError {
    fn from(src: TxManagerError) -> Self {
        match src {
            TxManagerError::Enclave(err) => Self::from(err),
            TxManagerError::TransactionValidation(err) => Self::from(err),
            TxManagerError::LedgerDb(err) => Self::from(err),
            _ => Self::Other(format!("tx manager error: {}", src)),
        }
    }
}

impl From<MintTxManagerError> for ConsensusGrpcError {
    fn from(src: MintTxManagerError) -> Self {
        match src {
            MintTxManagerError::MintValidation(err) => Self::from(err),
            MintTxManagerError::LedgerDb(err) => Self::from(err),
        }
    }
}

impl From<ConsensusGrpcError> for RpcStatus {
    fn from(src: ConsensusGrpcError) -> Self {
        match src {
            ConsensusGrpcError::RpcStatus(rpc_status) => rpc_status,
            ConsensusGrpcError::Ledger(err) => {
                RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("Ledger error: {}", err))
            }
            ConsensusGrpcError::OverCapacity => RpcStatus::with_message(
                RpcStatusCode::UNAVAILABLE,
                "Temporarily over capacity".into(),
            ),
            ConsensusGrpcError::NotServing => RpcStatus::with_message(
                RpcStatusCode::UNAVAILABLE,
                "Temporarily not serving requests".into(),
            ),
            ConsensusGrpcError::Enclave(EnclaveError::Attest(err)) => {
                global_log::error!("Permission denied: {}", err);
                RpcStatus::with_message(
                    RpcStatusCode::PERMISSION_DENIED,
                    "Permission Denied (attestation)".into(),
                )
            }
            ConsensusGrpcError::Other(err) => RpcStatus::with_message(RpcStatusCode::INTERNAL, err),
            ConsensusGrpcError::TransactionValidation(err) => {
                global_log::error!("Attempting to convert a ConsensusGrpcError::TransactionValidation into RpcStatus, this should not happen! Error is: {}", err);
                RpcStatus::with_message(
                    RpcStatusCode::INTERNAL,
                    format!("Unexpected transaction validation error: {}", err),
                )
            }
            _ => {
                RpcStatus::with_message(RpcStatusCode::INTERNAL, format!("Internal error: {}", src))
            }
        }
    }
}

/// Convert a `ConsensusGrpcError` into either `ProposeTxResponse` or
/// `RpcStatus`, depending on which error it holds.
impl From<ConsensusGrpcError> for Result<ProposeTxResponse, RpcStatus> {
    fn from(src: ConsensusGrpcError) -> Result<ProposeTxResponse, RpcStatus> {
        match src {
            ConsensusGrpcError::TransactionValidation(err) => {
                let mut resp = ProposeTxResponse::new();
                resp.set_result(ProposeTxResult::from(err));
                Ok(resp)
            }
            _ => Err(RpcStatus::from(src)),
        }
    }
}

/// Convert a `ConsensusGrpcError` into either `ProposeMintConfigTxResponse`
/// or `RpcStatus`, depending on which error it holds.
impl From<ConsensusGrpcError> for Result<ProposeMintConfigTxResponse, RpcStatus> {
    fn from(src: ConsensusGrpcError) -> Result<ProposeMintConfigTxResponse, RpcStatus> {
        match src {
            ConsensusGrpcError::TransactionValidation(_err) => {
                // let resp = ProposeMintConfigTxResponse::new();
                // TODO resp.set_result(ProposeMintConfigTxResult::from(err));
                // Ok(resp)
                todo!() // This should never happen
            }
            ConsensusGrpcError::MintValidation(err) => Ok(ProposeMintConfigTxResponse {
                result: Some(MintValidationResult::from(err)).into(),
                ..Default::default()
            }),
            _ => Err(RpcStatus::from(src)),
        }
    }
}
