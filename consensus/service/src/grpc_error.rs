// Copyright (c) 2018-2020 MobileCoin Inc.

use crate::tx_manager::TxManagerError;
use failure::Fail;
use grpcio::{RpcStatus, RpcStatusCode};
use mc_common::logger::global_log;
use mc_consensus_api::consensus_common::{ProposeTxResponse, ProposeTxResult};
use mc_consensus_enclave::Error as EnclaveError;
use mc_ledger_db::Error as LedgerError;
use mc_transaction_core::validation::TransactionValidationError;

#[derive(Debug, Fail)]
pub enum ConsensusGrpcError {
    /// Built-in grpc error
    #[fail(display = "GRPC Error: {:?}", _0)]
    RpcStatus(RpcStatus),

    /// Ledger-related error
    #[fail(display = "Ledger error: {}", _0)]
    Ledger(LedgerError),

    /// Service is over capacity.
    #[fail(display = "Over capacity")]
    OverCapacity,

    /// Service is currently not serving requests.
    #[fail(display = "Temporarily not serving requests")]
    NotServing,

    /// Enclave-related error.
    #[fail(display = "Enclave error: {}", _0)]
    Enclave(EnclaveError),

    /// Transaction validation error.
    #[fail(display = "Transaction validation error: {}", _0)]
    TransactionValidation(TransactionValidationError),

    /// Invalid argument.
    #[fail(display = "Invalid argument: {}", _0)]
    InvalidArgument(String),

    /// Other errors.
    #[fail(display = "Other error: {}", _0)]
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

impl From<ConsensusGrpcError> for RpcStatus {
    fn from(src: ConsensusGrpcError) -> Self {
        match src {
            ConsensusGrpcError::RpcStatus(rpc_status) => rpc_status,
            ConsensusGrpcError::Ledger(err) => RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some(format!("Ledger error: {}", err)),
            ),
            ConsensusGrpcError::OverCapacity => RpcStatus::new(
                RpcStatusCode::UNAVAILABLE,
                Some("Temporarily over capacity".into()),
            ),
            ConsensusGrpcError::NotServing => RpcStatus::new(
                RpcStatusCode::UNAVAILABLE,
                Some("Temporarily not serving requests".into()),
            ),
            ConsensusGrpcError::Enclave(EnclaveError::Attest(err)) => {
                global_log::error!("Permission denied: {}", err);
                RpcStatus::new(
                    RpcStatusCode::PERMISSION_DENIED,
                    Some("Permission Denied (attestation)".into()),
                )
            }
            ConsensusGrpcError::Other(err) => RpcStatus::new(RpcStatusCode::INTERNAL, Some(err)),
            ConsensusGrpcError::TransactionValidation(err) => {
                global_log::error!("Attempting to convert a ConsensusGrpcError::TransactionValidation into RpcStatus, this should not happen! Error is: {}", err);
                RpcStatus::new(
                    RpcStatusCode::INTERNAL,
                    Some(format!("Unexpected transaction validation error: {}", err)),
                )
            }
            _ => RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some(format!("Internal error: {}", src)),
            ),
        }
    }
}

/// Convert a `ConsensusGrpcError` into either `ProposeTxResponse` or `RpcStatus`, depending on which error
/// it holds.
impl Into<Result<ProposeTxResponse, RpcStatus>> for ConsensusGrpcError {
    fn into(self) -> Result<ProposeTxResponse, RpcStatus> {
        match self {
            Self::TransactionValidation(err) => {
                let mut resp = ProposeTxResponse::new();
                resp.set_result(ProposeTxResult::from(err));
                Ok(resp)
            }
            _ => Err(RpcStatus::from(self)),
        }
    }
}
