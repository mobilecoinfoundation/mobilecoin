// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Errors that can occur during ingest server operation

use crate::connection_error::Error as ConnectionError;

use displaydoc::Display;
use grpcio::Error as GrpcError;
use mc_api::ConversionError;
use mc_common::ResponderId;
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::report_parse::ReportParseError;
use mc_fog_ingest_enclave::Error as EnclaveError;
use mc_fog_recovery_db_iface::RecoveryDbError;
use mc_fog_sql_recovery_db::Error as SqlRecoveryDbError;
use mc_fog_uri::IngestPeerUri;
use mc_ledger_db::Error as LedgerDbError;
use mc_sgx_report_cache_api::Error as ReportableEnclaveError;
use mc_sgx_report_cache_untrusted::Error as ReportCacheError;
use mc_util_uri::{UriConversionError, UriParseError};
use std::collections::BTreeMap;

/// An error returned by the ingest service
#[derive(Debug, Display)]
pub enum IngestServiceError {
    /// Ingest enclave error: {0}
    Enclave(EnclaveError),
    /// LedgerDb Error: {0}
    LedgerDb(LedgerDbError),
    /// RecoveryDbError: {0}
    RecoveryDb(Box<dyn RecoveryDbError>),
    /// Serialization
    Serialization,
    /// ConnectionError: {0}
    Connection(ConnectionError),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
    /// Reportable enclave error: {0}
    ReportableEnclave(ReportableEnclaveError),
    /// Uri conversion error: {0}
    UriConversion(UriConversionError),
    /// Peer backup error: {0}
    Backup(PeerBackupError),
    /// This change not allowed unless server is idle
    ServerNotIdle,
    /**
     * When activating, the process was aborted because this key is already
     * retired: {0}
     */
    KeyAlreadyRetired(CompressedRistrettoPublic),
    /// Report publication and ingress key checkup operation failed
    PublishReport,
    /// IO Error: {0}
    Io(std::io::Error),
    /// GRPC Error: {0}
    Grpc(GrpcError),
    /// Report Parse: {0}
    ReportParse(ReportParseError),
}

impl From<EnclaveError> for IngestServiceError {
    fn from(src: EnclaveError) -> Self {
        Self::Enclave(src)
    }
}

impl From<LedgerDbError> for IngestServiceError {
    fn from(src: LedgerDbError) -> Self {
        Self::LedgerDb(src)
    }
}

impl From<ConnectionError> for IngestServiceError {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

impl From<SqlRecoveryDbError> for IngestServiceError {
    fn from(src: SqlRecoveryDbError) -> Self {
        Self::RecoveryDb(Box::new(src))
    }
}

impl From<mc_util_serial::encode::Error> for IngestServiceError {
    fn from(_: mc_util_serial::encode::Error) -> Self {
        Self::Serialization
    }
}

impl From<UriParseError> for IngestServiceError {
    fn from(_: UriParseError) -> Self {
        Self::Serialization
    }
}

impl From<ReportCacheError> for IngestServiceError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}

impl From<ReportableEnclaveError> for IngestServiceError {
    fn from(src: ReportableEnclaveError) -> Self {
        Self::ReportableEnclave(src)
    }
}

impl From<UriConversionError> for IngestServiceError {
    fn from(src: UriConversionError) -> Self {
        Self::UriConversion(src)
    }
}

impl From<PeerBackupError> for IngestServiceError {
    fn from(src: PeerBackupError) -> Self {
        Self::Backup(src)
    }
}

impl From<std::io::Error> for IngestServiceError {
    fn from(src: std::io::Error) -> Self {
        Self::Io(src)
    }
}

impl From<GrpcError> for IngestServiceError {
    fn from(src: GrpcError) -> Self {
        Self::Grpc(src)
    }
}

impl From<ReportParseError> for IngestServiceError {
    fn from(src: ReportParseError) -> Self {
        Self::ReportParse(src)
    }
}

/// An error which occurs when making or checking on a peer backup
#[derive(Debug, Display)]
pub enum PeerBackupError {
    /// Another peer is unexpectedly active: {0}
    AnotherActivePeer(IngestPeerUri),
    /// Failed to set peer {0} ingress key
    FailedRemoteKeyBackup(IngestPeerUri),
    /// Failed to set peer {0} peers list
    FailedRemoteSetPeers(IngestPeerUri),
    /// ConnectionError: {0}
    Connection(ConnectionError),
    /// Peer sent a bad igp URI: {0}
    PeerSentBadURI(UriParseError),
    /// Invalid protobuf structure from peer: {0:?}
    Conversion(ConversionError),
    /// A race when creating new ingress key, backing off
    CreatingNewIngressKey,
}

impl From<ConnectionError> for PeerBackupError {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

impl From<UriParseError> for PeerBackupError {
    fn from(src: UriParseError) -> Self {
        Self::PeerSentBadURI(src)
    }
}

impl From<ConversionError> for PeerBackupError {
    fn from(src: ConversionError) -> Self {
        Self::Conversion(src)
    }
}

/// An error which occurs when attempting to restore saved state of the server
#[derive(Debug, Display)]
pub enum RestoreStateError {
    /// Ingest enclave error: {0}
    Enclave(EnclaveError),
    /// ConnectionError: {0}
    Connection(ConnectionError),
    /// Report cache error: {0}
    ReportCache(ReportCacheError),
    /// Peer backup error: {0}
    Backup(PeerBackupError),
    /**
     * Ingress public key in state file didn't match what's in the enclave:
     * enclave has {0}, needed {1}
     */
    IngressKeyMismatch(CompressedRistrettoPublic, CompressedRistrettoPublic),
    /// Statefile contained invalid peer uri: {0}
    InvalidPeerUri(UriParseError),
    /// Statefile contained uri with no responder id: {0}
    ResponderId(UriConversionError),
    /// Setting peers from the statefile failed: {0}
    SetPeers(SetPeersError),
    /**
     * Server not in idle state before restore state operation, this is a
     * logic error
     */
    ServerNotIdle,
    /// Invalid data in protobuf: {0:?}
    Conversion(ConversionError),
}

impl From<EnclaveError> for RestoreStateError {
    fn from(src: EnclaveError) -> Self {
        Self::Enclave(src)
    }
}

impl From<ConnectionError> for RestoreStateError {
    fn from(src: ConnectionError) -> Self {
        Self::Connection(src)
    }
}

impl From<ReportCacheError> for RestoreStateError {
    fn from(src: ReportCacheError) -> Self {
        Self::ReportCache(src)
    }
}

impl From<PeerBackupError> for RestoreStateError {
    fn from(src: PeerBackupError) -> Self {
        Self::Backup(src)
    }
}

impl From<UriParseError> for RestoreStateError {
    fn from(src: UriParseError) -> Self {
        Self::InvalidPeerUri(src)
    }
}

impl From<ConversionError> for RestoreStateError {
    fn from(src: ConversionError) -> Self {
        Self::Conversion(src)
    }
}

impl From<SetPeersError> for RestoreStateError {
    fn from(src: SetPeersError) -> Self {
        Self::SetPeers(src)
    }
}

/// An error which occurs when attempting to set the list of peers
#[derive(Debug, Display)]
pub enum SetPeersError {
    /// Statefile contained uri with no responder id: {0}
    ResponderId(UriConversionError),
    /**
     * When setting our peers, our responder id was missing, so the peer set
     * operation was rejected: '{0}' is not a member of {1:?}
     */
    MissingOurResponderId(ResponderId, BTreeMap<ResponderId, IngestPeerUri>),
}

impl From<UriConversionError> for SetPeersError {
    fn from(src: UriConversionError) -> Self {
        Self::ResponderId(src)
    }
}
