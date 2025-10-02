// Copyright (c) 2018-2024 The MobileCoin Foundation

//! The mobilecoind Service
//! * provides a GRPC server
//! * creates a managing thread and thread pool that scans a local database
//! * processes all transactions to discover transactions for monitors
//! * writes matching transactions to a local DB, organized by subaddress_id

use crate::{
    database::Database,
    error::Error,
    monitor_store::{MonitorData, MonitorId},
    payments::{Outlay, OutlayV2, SciForTx, TransactionsManager, TxProposal},
    sync::SyncThread,
    transaction_memo::TransactionMemo,
    utxo_store::{UnspentTxOut, UtxoId},
};
use api::fog_ledger::{TxOutResult, TxOutResultCode};
use bip39::{Language, Mnemonic, MnemonicType};
use grpcio::{EnvBuilder, RpcContext, RpcStatus, RpcStatusCode, ServerBuilder, UnarySink};
use mc_account_keys::{
    burn_address, AccountKey, PublicAddress, RootIdentity, ShortAddressHash,
    DEFAULT_SUBADDRESS_INDEX,
};
use mc_api::{blockchain::ArchiveBlock, printable, printable::printable_wrapper};
use mc_blockchain_types::BlockIndex;
use mc_common::{
    logger::{log, Logger},
    HashMap,
};
use mc_connection::{BlockInfo, BlockchainConnection, UserTxConnection};
use mc_core::slip10::Slip10KeyGenerator;
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPrivate, RistrettoPublic};
use mc_fog_report_validation::FogPubkeyResolver;
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_ledger_sync::{NetworkState, PollingNetworkState};
use mc_mobilecoind_api::{
    self as api,
    mobilecoind_api::{create_mobilecoind_api, MobilecoindApi},
    MobilecoindUri,
};
use mc_transaction_builder::BurnRedemptionMemoBuilder;
use mc_transaction_core::{
    get_tx_out_shared_secret,
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipProof},
    Amount, MemoPayload, TokenId,
};
use mc_transaction_extra::{BurnRedemptionMemo, MemoType, TxOutConfirmationNumber};
use mc_util_from_random::FromRandom;
use mc_util_grpc::{
    rpc_internal_error, rpc_invalid_arg_error, rpc_logger, send_result, AdminService,
    BuildInfoService, ConnectionUriGrpcioServer,
};
use mc_watcher::watcher_db::WatcherDB;
use mc_watcher_api::TimestampResultCode;
use std::sync::{Arc, Mutex, RwLock};

pub struct Service {
    /// Sync thread.
    _sync_thread: Arc<Mutex<Option<SyncThread>>>,

    /// GRPC server.
    _server: grpcio::Server,
}

// for the root_entropy usage
#[allow(deprecated)]
impl Service {
    pub fn new<
        T: BlockchainConnection + UserTxConnection + 'static,
        FPR: FogPubkeyResolver + 'static,
    >(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        watcher_db: Option<WatcherDB>,
        transactions_manager: TransactionsManager<T, FPR>,
        network_state: Arc<RwLock<PollingNetworkState<T>>>,
        listen_uri: &MobilecoindUri,
        num_workers: Option<usize>,
        chain_id: String,
        logger: Logger,
    ) -> Self {
        let sync_thread = if mobilecoind_db.is_db_encrypted() {
            log::info!(logger, "Db encryption enabled, sync task would start once password is provided via the API.");
            Arc::new(Mutex::new(None))
        } else {
            log::info!(logger, "Starting mobilecoind sync task thread");
            Arc::new(Mutex::new(Some(SyncThread::start(
                ledger_db.clone(),
                mobilecoind_db.clone(),
                num_workers,
                logger.clone(),
            ))))
        };

        let start_sync_thread = {
            let ledger_db = ledger_db.clone();
            let mobilecoind_db = mobilecoind_db.clone();
            let logger = logger.clone();
            let sync_thread = sync_thread.clone();
            Arc::new(move || {
                let mut sync_thread = sync_thread.lock().expect("mutex poisoned");
                assert!(sync_thread.is_none());

                *sync_thread = Some(SyncThread::start(
                    ledger_db.clone(),
                    mobilecoind_db.clone(),
                    num_workers,
                    logger.clone(),
                ));
            })
        };

        let api = ServiceApi::new(
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            watcher_db,
            network_state,
            start_sync_thread,
            chain_id,
            logger.clone(),
        );

        // Package it into grpc service.
        let mobilecoind_service = create_mobilecoind_api(api);

        // Build info API service.
        let build_info_service = BuildInfoService::new(logger.clone()).into_service();

        // Health check service.
        let health_service = mc_util_grpc::HealthService::new(None, logger.clone()).into_service();

        // Admin service.
        let admin_service = AdminService::new(
            "mobilecoind".to_owned(),
            listen_uri.to_string(),
            None,
            logger.clone(),
        )
        .into_service();

        // Package service into grpc server.
        log::info!(logger, "Starting mobilecoind API Service on {}", listen_uri);
        let env = Arc::new(
            EnvBuilder::new()
                .cq_count(1)
                .name_prefix("Mobilecoind-RPC".to_string())
                .build(),
        );

        let server_builder = ServerBuilder::new(env)
            .register_service(admin_service)
            .register_service(build_info_service)
            .register_service(health_service)
            .register_service(mobilecoind_service);

        let mut server = server_builder
            .build_using_uri(listen_uri, logger.clone())
            .expect("Could not build gRPC server for the listen URI");
        server.start();

        Self {
            _server: server,
            _sync_thread: sync_thread,
        }
    }
}

pub struct ServiceApi<
    T: BlockchainConnection + UserTxConnection + 'static,
    FPR: FogPubkeyResolver + 'static,
> {
    transactions_manager: TransactionsManager<T, FPR>,
    ledger_db: LedgerDB,
    mobilecoind_db: Database,
    watcher_db: Option<WatcherDB>,
    network_state: Arc<RwLock<PollingNetworkState<T>>>,
    start_sync_thread: Arc<dyn Fn() + Send + Sync>,
    chain_id: String,
    logger: Logger,
}

impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver + 'static> Clone
    for ServiceApi<T, FPR>
{
    fn clone(&self) -> Self {
        Self {
            transactions_manager: self.transactions_manager.clone(),
            ledger_db: self.ledger_db.clone(),
            mobilecoind_db: self.mobilecoind_db.clone(),
            watcher_db: self.watcher_db.clone(),
            network_state: self.network_state.clone(),
            start_sync_thread: self.start_sync_thread.clone(),
            chain_id: self.chain_id.clone(),
            logger: self.logger.clone(),
        }
    }
}

#[allow(deprecated)]
impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver + 'static>
    ServiceApi<T, FPR>
{
    pub fn new(
        transactions_manager: TransactionsManager<T, FPR>,
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        watcher_db: Option<WatcherDB>,
        network_state: Arc<RwLock<PollingNetworkState<T>>>,
        start_sync_thread: Arc<dyn Fn() + Send + Sync>,
        chain_id: String,
        logger: Logger,
    ) -> Self {
        Self {
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            watcher_db,
            network_state,
            start_sync_thread,
            chain_id,
            logger,
        }
    }

    // Get last block info objects from network state for our peers
    // Make a copy to avoid holding RW lock
    fn get_last_block_infos(&self) -> Vec<BlockInfo> {
        self.network_state
            .read()
            .expect("lock poisoned")
            .peer_to_block_info()
            .values()
            .cloned()
            .collect()
    }

    fn get_version_impl(&self, _request: ()) -> Result<api::MobilecoindVersionResponse, RpcStatus> {
        Ok(api::MobilecoindVersionResponse {
            version: (env!("CARGO_PKG_VERSION").to_string()),
        })
    }

    fn add_monitor_impl(
        &mut self,
        request: api::AddMonitorRequest,
    ) -> Result<api::AddMonitorResponse, RpcStatus> {
        // Get the AccountKey from the GRPC request.
        let proto_account_key = request.account_key.as_ref().ok_or_else(|| {
            RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, "account_key".into())
        })?;
        let account_key = AccountKey::try_from(proto_account_key)
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // Populate a new `MonitorData` instance.
        let data = MonitorData::new(
            account_key,
            request.first_subaddress,
            request.num_subaddresses,
            request.first_block,
            &request.name,
        )
        .map_err(|err| rpc_internal_error("monitor_data.new", err, &self.logger))?;

        // Insert into database. Return the id and flag if the monitor already existed.
        let (id, is_new) = match self.mobilecoind_db.add_monitor(&data) {
            Ok(id) => Ok((id, true)),
            Err(Error::MonitorIdExists) => Ok((MonitorId::from(&data), false)),
            Err(err) => Err(err),
        }
        .map_err(|err| rpc_internal_error("mobilecoind_db.add_monitor", err, &self.logger))?;

        // Return success response.
        Ok(api::AddMonitorResponse {
            monitor_id: id.to_vec(),
            is_new,
        })
    }

    fn remove_monitor_impl(&mut self, request: api::RemoveMonitorRequest) -> Result<(), RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Remove from database.
        self.mobilecoind_db
            .remove_monitor(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.remove_monitor", err, &self.logger)
            })?;

        // Return success response.
        Ok(())
    }

    fn get_monitor_list_impl(
        &mut self,
        _request: (),
    ) -> Result<api::GetMonitorListResponse, RpcStatus> {
        let monitor_map: HashMap<MonitorId, MonitorData> =
            self.mobilecoind_db.get_monitor_map().map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_store_map", err, &self.logger)
            })?;

        Ok(api::GetMonitorListResponse {
            monitor_id_list: monitor_map.keys().map(|id| id.to_vec()).collect(),
        })
    }

    fn get_monitor_status_impl(
        &mut self,
        request: api::GetMonitorStatusRequest,
    ) -> Result<api::GetMonitorStatusResponse, RpcStatus> {
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        let status = api::MonitorStatus {
            account_key: Some(mc_api::external::AccountKey::from(&data.account_key)),
            first_subaddress: data.first_subaddress,
            num_subaddresses: data.num_subaddresses,
            first_block: data.first_block,
            next_block: data.next_block,
            ..Default::default()
        };

        Ok(api::GetMonitorStatusResponse {
            status: Some(status),
        })
    }

    fn get_unspent_tx_out_list_impl(
        &mut self,
        request: api::GetUnspentTxOutListRequest,
    ) -> Result<api::GetUnspentTxOutListResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_invalid_arg_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get UnspentTxOuts.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, request.subaddress_index)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Filter out those that don't have the requested token id
        let utxos: Vec<_> = utxos
            .into_iter()
            .filter(|utxo| utxo.token_id == request.token_id)
            .collect();

        // Convert to protos.
        let proto_utxos: Vec<api::UnspentTxOut> = utxos.iter().map(|utxo| utxo.into()).collect();

        // Return response.
        Ok(api::GetUnspentTxOutListResponse {
            output_list: proto_utxos,
        })
    }

    fn get_all_unspent_tx_out_impl(
        &mut self,
        request: api::GetAllUnspentTxOutRequest,
    ) -> Result<api::GetAllUnspentTxOutResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_invalid_arg_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get UnspentTxOuts.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_monitor(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_monitor", err, &self.logger)
            })?;

        // Convert to protos.
        let proto_utxos: Vec<api::UnspentTxOut> = utxos.iter().map(|utxo| utxo.into()).collect();

        // Return response.
        Ok(api::GetAllUnspentTxOutResponse {
            output_list: proto_utxos,
        })
    }

    fn generate_root_entropy_impl(
        &mut self,
        _request: (),
    ) -> Result<api::GenerateRootEntropyResponse, RpcStatus> {
        let mut rng = rand::thread_rng();
        let root_id = RootIdentity::from_random(&mut rng);
        Ok(api::GenerateRootEntropyResponse {
            root_entropy: root_id.root_entropy.as_ref().to_vec(),
        })
    }

    fn generate_mnemonic_impl(
        &mut self,
        _request: (),
    ) -> Result<api::GenerateMnemonicResponse, RpcStatus> {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);

        Ok(api::GenerateMnemonicResponse {
            mnemonic: mnemonic.phrase().to_string(),
            bip39_entropy: mnemonic.entropy().to_vec(),
        })
    }

    fn get_account_key_from_root_entropy_impl(
        &mut self,
        request: api::GetAccountKeyFromRootEntropyRequest,
    ) -> Result<api::GetAccountKeyResponse, RpcStatus> {
        // Get the entropy.
        if request.root_entropy.len() != 32 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "entropy".into(),
            ));
        }

        // Use root entropy to construct AccountKey.
        let mut root_entropy = [0u8; 32];
        root_entropy.copy_from_slice(request.root_entropy.as_slice());
        let root_id = RootIdentity::from(&root_entropy);
        let account_key = AccountKey::from(&root_id);

        // Return response.
        Ok(api::GetAccountKeyResponse {
            account_key: Some((&account_key).into()),
        })
    }

    fn get_account_key_from_mnemonic_impl(
        &mut self,
        request: api::GetAccountKeyFromMnemonicRequest,
    ) -> Result<api::GetAccountKeyResponse, RpcStatus> {
        let mnemonic = Mnemonic::from_phrase(&request.mnemonic, Language::English)
            .map_err(|err| rpc_invalid_arg_error("mnemonic", err, &self.logger))?;
        let key = mnemonic.derive_slip10_key(request.account_index);
        let account_key = AccountKey::from(key);

        // Return response.
        Ok(api::GetAccountKeyResponse {
            account_key: Some((&account_key).into()),
        })
    }

    fn get_public_address_impl(
        &mut self,
        request: api::GetPublicAddressRequest,
    ) -> Result<api::GetPublicAddressResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_invalid_arg_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data.
        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Verify subaddress falls in the range we are monitoring.
        if !data
            .subaddress_indexes()
            .contains(&request.subaddress_index)
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "subaddress_index".into(),
            ));
        }

        // Get the subaddress.
        let subaddress = data.account_key.subaddress(request.subaddress_index);

        // Also build the b58 wrapper
        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&subaddress).into(),
            )),
        };

        // Return response.
        Ok(api::GetPublicAddressResponse {
            public_address: Some((&subaddress).into()),
            b58_code: wrapper
                .b58_encode()
                .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?,
        })
    }

    fn get_short_address_hash_impl(
        &mut self,
        request: api::GetShortAddressHashRequest,
    ) -> Result<api::GetShortAddressHashResponse, RpcStatus> {
        let address = PublicAddress::try_from(
            request
                .public_address
                .as_ref()
                .unwrap_or(&Default::default()),
        )
        .map_err(|err| rpc_invalid_arg_error("PublicAddress.try_from", err, &self.logger))?;

        let hash = ShortAddressHash::from(&address);

        Ok(api::GetShortAddressHashResponse {
            hash: hash.as_ref().to_vec(),
        })
    }

    fn validate_authenticated_sender_memo_impl(
        &mut self,
        request: api::ValidateAuthenticatedSenderMemoRequest,
    ) -> Result<api::ValidateAuthenticatedSenderMemoResponse, RpcStatus> {
        // Read the utxo proto
        let utxo = UnspentTxOut::try_from(request.utxo.as_ref().unwrap_or(&Default::default()))
            .map_err(|err| rpc_invalid_arg_error("unspent_tx_out.try_from", err, &self.logger))?;

        let memo_payload = MemoPayload::try_from(&utxo.memo_payload[..])
            .map_err(|err| rpc_invalid_arg_error("memo_payload.try_from", err, &self.logger))?;

        // Read the sender proto
        let sender =
            PublicAddress::try_from(request.sender.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| rpc_invalid_arg_error("sender.try_from", err, &self.logger))?;

        // Get MonitorId from the GRPC request.
        let monitor_id = MonitorId::try_from(request.monitor_id.as_slice())
            .map_err(|err| rpc_invalid_arg_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data.
        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        let subaddress_vpk = data
            .account_key
            .subaddress_view_private(utxo.subaddress_index);
        let tx_out_public_key = &utxo.tx_out.public_key;

        let success = bool::from(match MemoType::try_from(&memo_payload) {
            Ok(MemoType::AuthenticatedSender(memo)) => {
                memo.validate(&sender, &subaddress_vpk, tx_out_public_key)
            }
            Ok(MemoType::AuthenticatedSenderWithPaymentRequestId(memo)) => {
                memo.validate(&sender, &subaddress_vpk, tx_out_public_key)
            }
            Ok(MemoType::AuthenticatedSenderWithPaymentIntentId(memo)) => {
                memo.validate(&sender, &subaddress_vpk, tx_out_public_key)
            }
            Ok(other) => {
                return Err(rpc_invalid_arg_error(
                    "Not an authenticated sender memo",
                    format!("{other:?}"),
                    &self.logger,
                ));
            }
            Err(err) => {
                return Err(rpc_invalid_arg_error(
                    "Not an authenticated sender memo",
                    format!("{err:?}"),
                    &self.logger,
                ));
            }
        });

        Ok(api::ValidateAuthenticatedSenderMemoResponse { success })
    }

    fn tx_out_view_key_match_impl(
        &mut self,
        request: api::TxOutViewKeyMatchRequest,
    ) -> Result<api::TxOutViewKeyMatchResponse, RpcStatus> {
        let tx_out = TxOut::try_from(request.txo.as_ref().unwrap_or(&Default::default()))
            .map_err(|err| rpc_internal_error("tx_out.try_from", err, &self.logger))?;
        let view_private_key = RistrettoPrivate::try_from(
            request
                .view_private_key
                .as_ref()
                .unwrap_or(&Default::default()),
        )
        .map_err(|err| rpc_invalid_arg_error("view_private_key.try_from", err, &self.logger))?;

        match tx_out.view_key_match(&view_private_key) {
            Ok((amount, shared_secret)) => {
                let shared_secret: mc_api::external::CompressedRistretto = (&shared_secret).into();

                Ok(api::TxOutViewKeyMatchResponse {
                    matched: true,
                    value: amount.value,
                    token_id: *amount.token_id,
                    shared_secret: Some(shared_secret),
                })
            }
            Err(_) => Ok(api::TxOutViewKeyMatchResponse {
                matched: false,
                ..Default::default()
            }),
        }
    }

    fn parse_request_code_impl(
        &mut self,
        request: api::ParseRequestCodeRequest,
    ) -> Result<api::ParseRequestCodeResponse, RpcStatus> {
        let wrapper = api::printable::PrintableWrapper::b58_decode(request.b58_code.to_string())
            .map_err(|err| rpc_internal_error("PrintableWrapper_b58_decode", err, &self.logger))?;

        match wrapper.wrapper {
            Some(printable_wrapper::Wrapper::PaymentRequest(payment_request)) => {
                Ok(api::ParseRequestCodeResponse {
                    receiver: payment_request.public_address,
                    value: payment_request.value,
                    memo: payment_request.memo,
                    token_id: payment_request.token_id,
                })
            }
            Some(printable_wrapper::Wrapper::PublicAddress(public_address)) => {
                Ok(api::ParseRequestCodeResponse {
                    receiver: Some(public_address),
                    value: 0,
                    memo: String::new(),
                    ..Default::default()
                })
            }
            _ => Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "Neither payment request nor public address".into(),
            )),
        }
    }

    fn create_request_code_impl(
        &mut self,
        request: api::CreateRequestCodeRequest,
    ) -> Result<api::CreateRequestCodeResponse, RpcStatus> {
        let receiver =
            PublicAddress::try_from(request.receiver.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let payment_request = api::printable::PaymentRequest {
            public_address: Some((&receiver).into()),
            value: request.value,
            memo: request.memo.clone(),
            token_id: request.token_id,
            ..Default::default()
        };

        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PaymentRequest(payment_request)),
        };

        let encoded = wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        Ok(api::CreateRequestCodeResponse { b58_code: encoded })
    }

    fn parse_transfer_code_impl(
        &mut self,
        request: api::ParseTransferCodeRequest,
    ) -> Result<api::ParseTransferCodeResponse, RpcStatus> {
        let wrapper = api::printable::PrintableWrapper::b58_decode(request.b58_code.to_string())
            .map_err(|err| rpc_internal_error("PrintableWrapper.b58_decode", err, &self.logger))?;

        let Some(printable_wrapper::Wrapper::TransferPayload(transfer_payload)) = wrapper.wrapper
        else {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "has_transfer_payload".into(),
            ));
        };

        let tx_public_key = RistrettoPublic::try_from(
            transfer_payload
                .tx_out_public_key
                .as_ref()
                .unwrap_or(&Default::default()),
        )
        .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let compressed_tx_public_key = CompressedRistrettoPublic::from(&tx_public_key);

        // build and include a UnspentTxOut that can be immediately spent
        let index = self
            .ledger_db
            .get_tx_out_index_by_public_key(&compressed_tx_public_key)
            .map_err(|err| match err {
                LedgerError::NotFound => {
                    RpcStatus::with_message(RpcStatusCode::NOT_FOUND, "tx_out not found".into())
                }
                _ => rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_public_key",
                    err,
                    &self.logger,
                ),
            })?;

        let tx_out = self.ledger_db.get_tx_out_by_index(index).map_err(|err| {
            rpc_internal_error("ledger_db.get_tx_out_by_index", err, &self.logger)
        })?;

        // Use bip39 or root entropy to construct AccountKey.
        let account_key = if !transfer_payload.bip39_entropy.is_empty() {
            let mnemonic = Mnemonic::from_entropy(
                transfer_payload.bip39_entropy.as_slice(),
                Language::English,
            )
            .map_err(|err| rpc_internal_error("Mnemonic.from_entropy", err, &self.logger))?;
            let key = mnemonic.derive_slip10_key(0);
            AccountKey::from(key)
        } else {
            let mut root_entropy = [0u8; 32];
            if root_entropy.len() != transfer_payload.root_entropy.len() {
                return Err(RpcStatus::with_message(
                    RpcStatusCode::INVALID_ARGUMENT,
                    "root_entropy".into(),
                ));
            }
            root_entropy.copy_from_slice(transfer_payload.root_entropy.as_slice());
            let root_id = RootIdentity::from(&root_entropy);
            AccountKey::from(&root_id)
        };

        let shared_secret =
            get_tx_out_shared_secret(account_key.view_private_key(), &tx_public_key);

        let (amount, _blinding) = tx_out
            .get_masked_amount()
            .map_err(|err| rpc_internal_error("tx_out.get_masked_amount", err, &self.logger))?
            .get_value(&shared_secret)
            .map_err(|err| rpc_internal_error("amount.get_value", err, &self.logger))?;

        let onetime_private_key = recover_onetime_private_key(
            &tx_public_key,
            account_key.view_private_key(),
            &account_key.subaddress_spend_private(DEFAULT_SUBADDRESS_INDEX),
        );

        let key_image = KeyImage::from(&onetime_private_key);

        let memo_payload = tx_out.decrypt_memo(&shared_secret).into();

        let utxo = UnspentTxOut {
            tx_out,
            subaddress_index: DEFAULT_SUBADDRESS_INDEX,
            key_image,
            value: amount.value,
            token_id: *amount.token_id,
            attempted_spend_height: 0,
            attempted_spend_tombstone: 0,
            memo_payload,
        };

        Ok(api::ParseTransferCodeResponse {
            root_entropy: transfer_payload.root_entropy,
            bip39_entropy: transfer_payload.bip39_entropy,
            tx_public_key: Some((&tx_public_key).into()),
            memo: transfer_payload.memo,
            utxo: Some((&utxo).into()),
        })
    }

    fn create_transfer_code_impl(
        &mut self,
        request: api::CreateTransferCodeRequest,
    ) -> Result<api::CreateTransferCodeResponse, RpcStatus> {
        // Must have entropy.
        if request.bip39_entropy.is_empty() && request.root_entropy.is_empty() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "bip39_entropy/root_entropy".into(),
            ));
        }

        // Only allow one type of entropy.
        if !request.bip39_entropy.is_empty() && !request.root_entropy.is_empty() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "bip39_entropy/root_entropy".into(),
            ));
        }

        // If we were provided with bip39 entropy, ensure it can be converted into a
        // mnemonic.
        if !request.bip39_entropy.is_empty()
            && Mnemonic::from_entropy(request.bip39_entropy.as_slice(), Language::English).is_err()
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "bip39_entropy".into(),
            ));
        }

        // If we were provided with root entropy, ensure it is 32 bytes long.
        if !request.root_entropy.is_empty() && request.root_entropy.len() != 32 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "bip39_entropy".into(),
            ));
        }

        // Tx public key must be 32 bytes long.
        if request
            .tx_public_key
            .as_ref()
            .unwrap_or(&Default::default())
            .data
            .len()
            != 32
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "tx_public_key".into(),
            ));
        }

        let transfer_payload = api::printable::TransferPayload {
            root_entropy: request.root_entropy,
            bip39_entropy: request.bip39_entropy,
            tx_out_public_key: request.tx_public_key,
            memo: request.memo,
        };

        let transfer_wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::TransferPayload(
                transfer_payload,
            )),
        };

        let encoded = transfer_wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        Ok(api::CreateTransferCodeResponse { b58_code: encoded })
    }

    fn parse_address_code_impl(
        &mut self,
        request: api::ParseAddressCodeRequest,
    ) -> Result<api::ParseAddressCodeResponse, RpcStatus> {
        let wrapper = api::printable::PrintableWrapper::b58_decode(request.b58_code.to_string())
            .map_err(|err| {
                rpc_invalid_arg_error("PrintableWrapper_b58_decode", err, &self.logger)
            })?;

        match wrapper.wrapper {
            Some(printable_wrapper::Wrapper::PaymentRequest(printable::PaymentRequest {
                public_address: Some(public_address),
                ..
            })) => Ok(api::ParseAddressCodeResponse {
                receiver: Some(public_address),
            }),
            Some(printable_wrapper::Wrapper::PublicAddress(public_address)) => {
                Ok(api::ParseAddressCodeResponse {
                    receiver: Some(public_address),
                })
            }
            _ => Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "Neither payment request nor public address".into(),
            )),
        }
    }

    fn create_address_code_impl(
        &mut self,
        request: api::CreateAddressCodeRequest,
    ) -> Result<api::CreateAddressCodeResponse, RpcStatus> {
        let receiver =
            PublicAddress::try_from(request.receiver.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&receiver).into(),
            )),
        };

        let encoded = wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        Ok(api::CreateAddressCodeResponse { b58_code: encoded })
    }

    /// Get mixins
    fn get_mixins_impl(
        &mut self,
        request: api::GetMixinsRequest,
    ) -> Result<api::GetMixinsResponse, RpcStatus> {
        let num_mixins: usize = request.num_mixins as usize;
        let excluded: Vec<TxOut> = request
            .excluded
            .iter()
            .map(|tx_out| {
                // Proto -> Rust struct conversion.
                TxOut::try_from(tx_out)
                    .map_err(|err| rpc_internal_error("tx_out.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<TxOut>, RpcStatus>>()?;

        let excluded_indexes = excluded
            .iter()
            .enumerate()
            .map(|(idx, tx_out)| {
                self.ledger_db
                    .get_tx_out_index_by_hash(&tx_out.hash())
                    .map_err(|err| match err {
                        LedgerError::NotFound => RpcStatus::with_message(
                            RpcStatusCode::NOT_FOUND,
                            format!("tx_out {idx} not found"),
                        ),
                        _ => rpc_internal_error("get_tx_out_index_by_hash", err, &self.logger),
                    })
            })
            .collect::<Result<Vec<u64>, RpcStatus>>()?;

        let mixins_with_proofs: Vec<(TxOut, TxOutMembershipProof)> = self
            .transactions_manager
            .get_rings(num_mixins, 1, &excluded_indexes)
            .map(|nested| nested.into_iter().flatten().collect())
            .map_err(|e| rpc_internal_error("get_rings_error", e, &self.logger))?; // TODO better error handling

        let tx_outs_with_proofs: Vec<api::TxOutWithProof> = mixins_with_proofs
            .iter()
            .map(|(tx_out, proof)| api::TxOutWithProof {
                output: Some(tx_out.into()),
                proof: Some(proof.into()),
            })
            .collect();

        Ok(api::GetMixinsResponse {
            mixins: tx_outs_with_proofs,
        })
    }

    /// Get a proof of membership for each requested TxOut.
    fn get_membership_proofs_impl(
        &mut self,
        request: api::GetMembershipProofsRequest,
    ) -> Result<api::GetMembershipProofsResponse, RpcStatus> {
        let outputs: Vec<TxOut> = match (request.outputs.is_empty(), request.indices.is_empty()) {
            // No outputs but indices are provided
            (true, false) => request
                .indices
                .iter()
                .map(|idx| {
                    self.ledger_db
                        .get_tx_out_by_index(*idx)
                        .map_err(|err| match err {
                            LedgerError::NotFound => RpcStatus::with_message(
                                RpcStatusCode::NOT_FOUND,
                                format!("tx_out {idx} not found"),
                            ),
                            _ => rpc_invalid_arg_error("get_tx_out_by_index", err, &self.logger),
                        })
                })
                .collect::<Result<Vec<TxOut>, RpcStatus>>()?,

            // Outputs and no indices
            (false, true) => {
                request
                    .outputs
                    .iter()
                    .map(|tx_out| {
                        // Proto -> Rust struct conversion.
                        TxOut::try_from(tx_out)
                            .map_err(|err| rpc_internal_error("tx_out.try_from", err, &self.logger))
                    })
                    .collect::<Result<Vec<TxOut>, RpcStatus>>()?
            }

            // No outputs or indices
            (true, true) => vec![],

            // Both outputs and indices
            (false, false) => {
                return Err(rpc_invalid_arg_error(
                    "request",
                    "cannot provide both outputs and indices",
                    &self.logger,
                ))
            }
        };

        let proofs: Vec<TxOutMembershipProof> = self
            .transactions_manager
            .get_membership_proofs(&outputs)
            .map_err(|err| rpc_internal_error("get_membership_proofs", err, &self.logger))?;

        Ok(api::GetMembershipProofsResponse {
            output_list: outputs
                .iter()
                .zip(proofs.iter())
                .map(|(tx_out, proof)| api::TxOutWithProof {
                    output: Some(tx_out.into()),
                    proof: Some(proof.into()),
                })
                .collect(),
        })
    }

    fn generate_tx_impl(
        &mut self,
        request: api::GenerateTxRequest,
    ) -> Result<api::GenerateTxResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Check that change_subaddress is covered by this monitor.
        if !sender_monitor_data
            .subaddress_indexes()
            .contains(&request.change_subaddress)
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "change_subaddress".into(),
            ));
        }

        // Get the list of potential inputs passed to.
        let input_list: Vec<UnspentTxOut> = request
            .input_list
            .iter()
            .enumerate()
            .map(|(i, proto_utxo)| {
                // Proto -> Rust struct conversion.
                let utxo = UnspentTxOut::try_from(proto_utxo).map_err(|err| {
                    rpc_internal_error("unspent_tx_out.try_from", err, &self.logger)
                })?;

                // Verify token id matches.
                if utxo.token_id != request.token_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list[{i}].token_id"),
                    ));
                }

                // Verify this output belongs to the monitor.
                let subaddress_id = self
                    .mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(&utxo))
                    .map_err(|err| {
                        rpc_internal_error(
                            "mobilecoind_db.get_subaddress_id_by_utxo_id",
                            err,
                            &self.logger,
                        )
                    })?;

                if subaddress_id.monitor_id != sender_monitor_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list.{i}"),
                    ));
                }

                // Success.
                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .outlay_list
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Get transaction memo builder.
        let transaction_memo =
            TransactionMemo::try_from(request.memo.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| {
                    rpc_invalid_arg_error("transaction_memo.try_from", err, &self.logger)
                })?;
        let memo_builder = transaction_memo.memo_builder(&sender_monitor_data.account_key);

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                TokenId::from(request.token_id),
                request.change_subaddress,
                &input_list,
                &outlays,
                &self.get_last_block_infos(),
                request.fee,
                request.tombstone,
                memo_builder,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        // Success.
        Ok(api::GenerateTxResponse {
            tx_proposal: Some((&tx_proposal).into()),
        })
    }

    fn generate_mixed_tx_impl(
        &mut self,
        request: api::GenerateMixedTxRequest,
    ) -> Result<api::GenerateMixedTxResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Check that change_subaddress is covered by this monitor.
        if !sender_monitor_data
            .subaddress_indexes()
            .contains(&request.change_subaddress)
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "change_subaddress".into(),
            ));
        }

        // Get the list of potential inputs passed to.
        let input_list: Vec<UnspentTxOut> = request
            .input_list
            .iter()
            .enumerate()
            .map(|(i, proto_utxo)| {
                // Proto -> Rust struct conversion.
                let utxo = UnspentTxOut::try_from(proto_utxo).map_err(|err| {
                    rpc_internal_error("unspent_tx_out.try_from", err, &self.logger)
                })?;

                // Verify this output belongs to the monitor.
                let subaddress_id = self
                    .mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(&utxo))
                    .map_err(|err| {
                        rpc_internal_error(
                            "mobilecoind_db.get_subaddress_id_by_utxo_id",
                            err,
                            &self.logger,
                        )
                    })?;

                if subaddress_id.monitor_id != sender_monitor_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list.{i}"),
                    ));
                }

                // Success.
                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        // Get the list of outlays.
        let outlays: Vec<OutlayV2> = request
            .outlay_list
            .iter()
            .map(OutlayV2::try_from)
            .collect::<Result<_, _>>()
            .map_err(|err| rpc_internal_error("outlay_v2.try_from", err, &self.logger))?;

        // Get the list of SCIs
        let scis: Vec<SciForTx> = request
            .scis
            .iter()
            .map(SciForTx::try_from)
            .collect::<Result<_, _>>()
            .map_err(|err| rpc_internal_error("sci_from_tx.try_from", err, &self.logger))?;

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_mixed_transaction(
                &sender_monitor_id,
                TokenId::from(request.fee_token_id),
                request.change_subaddress,
                &input_list,
                &scis,
                &outlays,
                &self.get_last_block_infos(),
                request.fee,
                request.tombstone,
                None, // opt_memo_builder
            )
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.build_mixed_transaction",
                    err,
                    &self.logger,
                )
            })?;

        // Success.
        Ok(api::GenerateMixedTxResponse {
            tx_proposal: Some((&tx_proposal).into()),
        })
    }

    fn generate_optimization_tx_impl(
        &mut self,
        request: api::GenerateOptimizationTxRequest,
    ) -> Result<api::GenerateOptimizationTxResponse, RpcStatus> {
        // Get monitor id from request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Generate optimization tx.
        let tx_proposal = self
            .transactions_manager
            .generate_optimization_tx(
                &monitor_id,
                request.subaddress,
                TokenId::from(request.token_id),
                &self.get_last_block_infos(),
                request.fee,
            )
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.generate_optimization_tx",
                    err,
                    &self.logger,
                )
            })?;

        // Success.
        Ok(api::GenerateOptimizationTxResponse {
            tx_proposal: Some((&tx_proposal).into()),
        })
    }

    fn generate_tx_from_tx_out_list_impl(
        &mut self,
        request: api::GenerateTxFromTxOutListRequest,
    ) -> Result<api::GenerateTxFromTxOutListResponse, RpcStatus> {
        let proto_account_key = request.account_key.as_ref().ok_or_else(|| {
            RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, "account_key".into())
        })?;

        let account_key = AccountKey::try_from(proto_account_key)
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        let token_id = TokenId::from(request.token_id);

        let input_list: Vec<UnspentTxOut> = request
            .input_list
            .iter()
            .enumerate()
            .map(|(i, proto_utxo)| {
                // Proto -> Rust struct conversion.
                let utxo = UnspentTxOut::try_from(proto_utxo).map_err(|err| {
                    rpc_internal_error("unspent_tx_out.try_from", err, &self.logger)
                })?;

                // Ensure token id matches.
                if utxo.token_id != *token_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list[{i}].token_id"),
                    ));
                }

                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        let receiver =
            PublicAddress::try_from(request.receiver.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let tx_proposal = self
            .transactions_manager
            .generate_tx_from_tx_list(
                &account_key,
                token_id,
                &input_list,
                &receiver,
                &self.get_last_block_infos(),
                request.fee,
            )
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.generate_tx_from_tx_list",
                    err,
                    &self.logger,
                )
            })?;

        Ok(api::GenerateTxFromTxOutListResponse {
            tx_proposal: Some((&tx_proposal).into()),
        })
    }

    fn generate_burn_redemption_tx_impl(
        &mut self,
        request: api::GenerateBurnRedemptionTxRequest,
    ) -> Result<api::GenerateBurnRedemptionTxResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Check that change_subaddress is covered by this monitor.
        if !sender_monitor_data
            .subaddress_indexes()
            .contains(&request.change_subaddress)
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "change_subaddress".into(),
            ));
        }

        // Get the list of potential inputs passed to.
        let input_list: Vec<UnspentTxOut> = request
            .input_list
            .iter()
            .enumerate()
            .map(|(i, proto_utxo)| {
                // Proto -> Rust struct conversion.
                let utxo = UnspentTxOut::try_from(proto_utxo).map_err(|err| {
                    rpc_internal_error(format!("unspent_tx_out[{i}].try_from"), err, &self.logger)
                })?;

                // Verify token id matches.
                if utxo.token_id != request.token_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list[{i}].token_id"),
                    ));
                }

                // Verify this output belongs to the monitor.
                let subaddress_id = self
                    .mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(&utxo))
                    .map_err(|err| {
                        rpc_internal_error(
                            "mobilecoind_db.get_subaddress_id_by_utxo_id",
                            err,
                            &self.logger,
                        )
                    })?;

                if subaddress_id.monitor_id != sender_monitor_id {
                    return Err(RpcStatus::with_message(
                        RpcStatusCode::INVALID_ARGUMENT,
                        format!("input_list[{i}].monitor_id"),
                    ));
                }

                // Success.
                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        // Generate the list of outlays.
        let outlays = vec![Outlay {
            value: request.burn_amount,
            receiver: burn_address(),
            tx_private_key: None,
        }];

        // Create memo builder.
        let mut memo_data = request.redemption_memo.to_vec();
        if memo_data.is_empty() {
            memo_data.resize(BurnRedemptionMemo::MEMO_DATA_LEN, 0);
        }
        let memo_data_array = memo_data.try_into().map_err(|_err| {
            RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, "redemption_memo".into())
        })?;

        let mut memo_builder = BurnRedemptionMemoBuilder::new(memo_data_array);
        if request.enable_destination_memo {
            memo_builder.enable_destination_memo();
        }

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                TokenId::from(request.token_id),
                request.change_subaddress,
                &input_list,
                &outlays,
                &self.get_last_block_infos(),
                request.fee,
                request.tombstone,
                Box::new(memo_builder),
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        // Success.
        Ok(api::GenerateBurnRedemptionTxResponse {
            tx_proposal: Some((&tx_proposal).into()),
        })
    }

    fn generate_transfer_code_tx_impl(
        &mut self,
        request: api::GenerateTransferCodeTxRequest,
    ) -> Result<api::GenerateTransferCodeTxResponse, RpcStatus> {
        // Generate entropy.
        let mnemonic_response = self.generate_mnemonic_impl(())?;
        let mnemonic_str = mnemonic_response.mnemonic.to_string();
        let bip39_entropy = mnemonic_response.bip39_entropy;

        // Generate a new account using this mnemonic.
        let account_key_request = api::GetAccountKeyFromMnemonicRequest {
            mnemonic: mnemonic_str,
            ..Default::default()
        };

        let account_key_response = self.get_account_key_from_mnemonic_impl(account_key_request)?;
        let account_key = AccountKey::try_from(
            account_key_response
                .account_key
                .as_ref()
                .unwrap_or(&Default::default()),
        )
        .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // The outlay we are sending the money to.
        let outlay = Outlay {
            receiver: account_key.default_subaddress(),
            value: request.value,
            tx_private_key: None,
        };

        // Generate transaction.
        let generate_tx_request = api::GenerateTxRequest {
            sender_monitor_id: request.sender_monitor_id,
            change_subaddress: request.change_subaddress,
            input_list: request.input_list.to_vec(),
            outlay_list: vec![(&outlay).into()],
            fee: request.fee,
            tombstone: request.tombstone,
            token_id: request.token_id,
            ..Default::default()
        };

        let generate_tx_response = self.generate_tx_impl(generate_tx_request)?;
        let tx_proposal = generate_tx_response.tx_proposal.unwrap_or_default();

        // Grab the public key of the relevant tx out.
        let proto_tx_public_key = {
            // We expect only a single outlay.
            if tx_proposal.outlay_index_to_tx_out_index.len() != 1 {
                return Err(RpcStatus::with_message(
                    RpcStatusCode::INTERNAL,
                    format!(
                        "outlay_index_to_tx_out_index contains {} elements, was expecting 1",
                        tx_proposal.outlay_index_to_tx_out_index.len()
                    ),
                ));
            }

            // Get the TxOut index of our single outlay.
            let tx_out_index = tx_proposal
                .outlay_index_to_tx_out_index
                .get(&0)
                .ok_or_else(|| {
                    RpcStatus::with_message(
                        RpcStatusCode::INTERNAL,
                        "outlay_index_to_tx_out_index doesn't contain index 0".to_owned(),
                    )
                })?;

            let default_tx_out = Default::default();
            let default_tx_prefix = Default::default();
            // Get the TxOut
            let tx_out = tx_proposal
                .tx
                .as_ref()
                .unwrap_or(&default_tx_out)
                .prefix
                .as_ref()
                .unwrap_or(&default_tx_prefix)
                .outputs
                .get(*tx_out_index as usize)
                .ok_or_else(|| {
                    RpcStatus::with_message(
                        RpcStatusCode::INTERNAL,
                        format!("tx out index {tx_out_index} not found"),
                    )
                })?;

            // Get the public key
            tx_out
                .public_key
                .as_ref()
                .unwrap_or(&Default::default())
                .clone()
        };

        let tx_public_key = RistrettoPublic::try_from(&proto_tx_public_key)
            .map_err(|err| rpc_internal_error("ristretto_public.try_from", err, &self.logger))?;

        let transfer_payload = api::printable::TransferPayload {
            bip39_entropy: bip39_entropy.to_vec(),
            tx_out_public_key: Some((&tx_public_key).into()),
            memo: request.memo.to_string(),
            ..Default::default()
        };

        let transfer_wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::TransferPayload(
                transfer_payload,
            )),
        };

        let b58_code = transfer_wrapper
            .b58_encode()
            .map_err(|err| rpc_internal_error("b58_encode", err, &self.logger))?;

        // Construct response.
        Ok(api::GenerateTransferCodeTxResponse {
            tx_proposal: Some(tx_proposal),
            bip39_entropy: bip39_entropy.to_vec(),
            tx_public_key: Some((&tx_public_key).into()),
            memo: request.memo.to_string(),
            b58_code,
        })
    }

    fn generate_swap_impl(
        &mut self,
        request: api::GenerateSwapRequest,
    ) -> Result<api::GenerateSwapResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Check that change_subaddress is covered by this monitor.
        if !sender_monitor_data
            .subaddress_indexes()
            .contains(&request.change_subaddress)
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "change_subaddress".into(),
            ));
        }

        // Get the utxo we are signing for
        let proto_utxo = request.input.as_ref().ok_or_else(|| {
            RpcStatus::with_message(RpcStatusCode::INVALID_ARGUMENT, "input".into())
        })?;

        let utxo = UnspentTxOut::try_from(proto_utxo)
            .map_err(|err| rpc_internal_error("unspent_tx_out.try_from", err, &self.logger))?;

        // Verify this output belongs to the monitor.
        let subaddress_id = self
            .mobilecoind_db
            .get_subaddress_id_by_utxo_id(&UtxoId::from(&utxo))
            .map_err(|err| {
                rpc_internal_error(
                    "mobilecoind_db.get_subaddress_id_by_utxo_id",
                    err,
                    &self.logger,
                )
            })?;

        if subaddress_id.monitor_id != sender_monitor_id {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "input.monitor_id".to_string(),
            ));
        }

        if request.counter_value == 0 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "counter_value".to_string(),
            ));
        }

        let counter_amount = Amount::new(request.counter_value, request.counter_token_id.into());

        // Attempt to construct an sci
        let sci = self
            .transactions_manager
            .build_swap_proposal(
                &sender_monitor_id,
                request.change_subaddress,
                &utxo,
                counter_amount,
                request.allow_partial_fill,
                request.minimum_fill_value,
                &self.get_last_block_infos(),
                request.tombstone,
                None, // opt_memo_builder
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.generate_swap", err, &self.logger)
            })?;

        Ok(api::GenerateSwapResponse {
            sci: Some((&sci).into()),
        })
    }

    fn submit_tx_impl(
        &mut self,
        request: api::SubmitTxRequest,
    ) -> Result<api::SubmitTxResponse, RpcStatus> {
        // Get TxProposal from request.
        let tx_proposal =
            TxProposal::try_from(request.tx_proposal.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| rpc_internal_error("tx_proposal.try_from", err, &self.logger))?;

        // Submit to network.
        let block_height = self
            .transactions_manager
            .submit_tx_proposal(&tx_proposal)
            .map_err(|err| {
                rpc_internal_error("transactions_manager.submit_tx_proposal", err, &self.logger)
            })?;

        // Update the attempted spend block height in db. Note that we swallow the error
        // here since our transaction did get sent to the network, and its
        // better to have the user attempt a double spend by having stale
        // UnspentTxOut data than having them not be aware that the transaction
        // was submitted.
        let utxo_ids: Vec<UtxoId> = tx_proposal.utxos.iter().map(UtxoId::from).collect();
        if let Err(err) = self.mobilecoind_db.update_attempted_spend(
            &utxo_ids,
            block_height,
            tx_proposal.tx.prefix.tombstone_block,
        ) {
            log::error!(
                self.logger,
                "failed updating attempted_spend_height after submitting tx {}: {:?}",
                tx_proposal.tx,
                err
            );
        }

        // Construct sender receipt.
        let sender_tx_receipt = api::SenderTxReceipt {
            key_image_list: tx_proposal
                .utxos
                .iter()
                .map(|utxo| (&utxo.key_image).into())
                .collect(),
            tombstone: tx_proposal.tx.prefix.tombstone_block,
        };

        // Construct receiver receipts.
        let receiver_tx_receipts: Vec<_> = tx_proposal
            .outlays
            .iter()
            .enumerate()
            .map(|(outlay_index, outlay)| {
                let tx_out_index = tx_proposal
                    .outlay_index_to_tx_out_index
                    .get(&outlay_index)
                    .ok_or_else(|| {
                        RpcStatus::with_message(
                            RpcStatusCode::INVALID_ARGUMENT,
                            "outlay_index_to_tx_out_index".into(),
                        )
                    })?;

                let tx_out = tx_proposal
                    .tx
                    .prefix
                    .outputs
                    .get(*tx_out_index)
                    .ok_or_else(|| {
                        RpcStatus::with_message(
                            RpcStatusCode::INVALID_ARGUMENT,
                            "outlay_index_to_tx_out_index".into(),
                        )
                    })?;

                let mut receiver_tx_receipt = api::ReceiverTxReceipt {
                    recipient: Some((&outlay.receiver).into()),
                    tx_public_key: Some((&tx_out.public_key).into()),
                    tx_out_hash: tx_out.hash().to_vec(),
                    tombstone: tx_proposal.tx.prefix.tombstone_block,
                    ..Default::default()
                };

                if tx_proposal.outlay_confirmation_numbers.len() > outlay_index {
                    receiver_tx_receipt.confirmation_number =
                        tx_proposal.outlay_confirmation_numbers[outlay_index].to_vec();
                }

                Ok(receiver_tx_receipt)
            })
            .collect::<Result<Vec<api::ReceiverTxReceipt>, RpcStatus>>()?;

        // Return response.
        Ok(api::SubmitTxResponse {
            sender_tx_receipt: Some(sender_tx_receipt),
            receiver_tx_receipt_list: receiver_tx_receipts,
        })
    }

    fn get_ledger_info_impl(
        &mut self,
        _request: (),
    ) -> Result<api::GetLedgerInfoResponse, RpcStatus> {
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        let num_txos = self
            .ledger_db
            .num_txos()
            .map_err(|err| rpc_internal_error("ledger_db.num_txos", err, &self.logger))?;

        Ok(api::GetLedgerInfoResponse {
            block_count: num_blocks,
            txo_count: num_txos,
        })
    }

    fn get_block_info_impl(
        &mut self,
        request: api::GetBlockInfoRequest,
    ) -> Result<api::GetBlockInfoResponse, RpcStatus> {
        let block_contents = self
            .ledger_db
            .get_block_contents(request.block)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_contents", err, &self.logger))?;

        let num_tx_outs = block_contents.outputs.len();
        let num_key_images = block_contents.key_images.len();

        // Return response.
        Ok(api::GetBlockInfoResponse {
            key_image_count: num_key_images as u64,
            txo_count: num_tx_outs as u64,
        })
    }

    fn get_block_impl(
        &mut self,
        request: api::GetBlockRequest,
    ) -> Result<api::GetBlockResponse, RpcStatus> {
        let block_data = self
            .ledger_db
            .get_block_data(request.block)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_data", err, &self.logger))?;

        let mut response = api::GetBlockResponse {
            block: Some(mc_consensus_api::blockchain::Block::from(
                block_data.block(),
            )),
            key_images: block_data
                .contents()
                .key_images
                .iter()
                .map(Into::into)
                .collect(),
            txos: block_data
                .contents()
                .outputs
                .iter()
                .map(Into::into)
                .collect(),
            ..Default::default()
        };

        if let Some(watcher_db) = self.watcher_db.as_ref() {
            let signatures = watcher_db
                .get_block_signatures(request.block)
                .map_err(|err| {
                    rpc_internal_error("watcher_db.get_block_signatures", err, &self.logger)
                })?;
            for signature_data in signatures.iter() {
                let signature_message = api::ArchiveBlockSignatureData {
                    src_url: signature_data.src_url.clone(),
                    filename: signature_data.archive_filename.clone(),
                    signature: Some((&signature_data.block_signature).into()),
                };
                response.signatures.push(signature_message);
            }
        }

        let (timestamp, timestamp_result_code) = self.get_block_timestamp(request.block);
        response.set_timestamp_result_code((&timestamp_result_code).into());
        response.timestamp = timestamp;

        Ok(response)
    }

    fn get_latest_block_impl(&mut self, _request: ()) -> Result<api::GetBlockResponse, RpcStatus> {
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        let request = api::GetBlockRequest {
            block: num_blocks - 1,
        };

        self.get_block_impl(request)
    }

    fn get_blocks_data_impl(
        &self,
        request: api::GetBlocksDataRequest,
    ) -> Result<api::GetBlocksDataResponse, RpcStatus> {
        let mut results = Vec::with_capacity(request.blocks.len());

        let latest_block: mc_api::blockchain::Block = (&self
            .ledger_db
            .get_latest_block()
            .map_err(|err| rpc_internal_error("ledger_db.get_latest_block", err, &self.logger))?)
            .into();

        for block_index in request.blocks.iter() {
            let block_data = match self.ledger_db.get_block_data(*block_index) {
                Ok(block_data) => block_data,
                Err(LedgerError::NotFound) => {
                    results.push(api::BlockDataWithTimestamp {
                        block_index: *block_index,
                        found: false,
                        ..Default::default()
                    });
                    continue;
                }
                Err(err) => {
                    return Err(rpc_internal_error(
                        "ledger_db.get_block_data",
                        err,
                        &self.logger,
                    ));
                }
            };

            let (block_timestamp, block_timestamp_result_code) =
                self.get_block_timestamp(*block_index);

            results.push(api::BlockDataWithTimestamp {
                block_index: *block_index,
                found: true,
                block_data: Some(ArchiveBlock::from(&block_data)),
                timestamp_result_code: block_timestamp_result_code as i32,
                timestamp: block_timestamp,
            });
        }

        Ok(api::GetBlocksDataResponse {
            results,
            latest_block: Some(latest_block),
        })
    }

    fn get_tx_status_as_sender_impl(
        &mut self,
        request: api::SubmitTxResponse,
    ) -> Result<api::GetTxStatusAsSenderResponse, RpcStatus> {
        let sender_tx_receipt = request.sender_tx_receipt.unwrap_or_default();
        let receiver_tx_receipt_list = request.receiver_tx_receipt_list;
        // Sanity-test the request.
        if sender_tx_receipt.key_image_list.is_empty() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "sender_receipt.key_image_list".into(),
            ));
        }

        if sender_tx_receipt.tombstone == 0 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "sender_receipt.tombstone".into(),
            ));
        }

        // Receiver receipt should have at least one output
        if receiver_tx_receipt_list.is_empty() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "receiver_receipt.receiver_tx_receipt_list".into(),
            ));
        }

        // Get list of key images from the request.
        let key_images: Vec<KeyImage> = sender_tx_receipt
            .key_image_list
            .iter()
            .map(|key_image| {
                KeyImage::try_from(key_image)
                    .map_err(|err| rpc_internal_error("key_image.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<KeyImage>, RpcStatus>>()?;

        // Get list of tx_public_keys from the request.
        let compressed_pubkeys: Vec<CompressedRistrettoPublic> = receiver_tx_receipt_list
            .iter()
            .map(|r| {
                RistrettoPublic::try_from(r.tx_public_key.as_ref().unwrap_or(&Default::default()))
                    .map_err(|err| {
                        rpc_internal_error("RistrettoPublic.try_from", err, &self.logger)
                    })
                    .map(|pubkey| CompressedRistrettoPublic::from(&pubkey))
            })
            .collect::<Result<Vec<CompressedRistrettoPublic>, RpcStatus>>()?;

        // Check the tx_public_keys in the receiver receipt, to also get the
        // block_height. Note that if the transaction has not yet landed, the
        // result will be a vec of LedgerDb::NotFound errors.
        let found_pubkey_indices: Vec<u64> = compressed_pubkeys
            .iter()
            .map(|compressed_tx_public_key| {
                self.ledger_db
                    .get_tx_out_index_by_public_key(compressed_tx_public_key)
                    .and_then(|txo_index| self.ledger_db.get_block_index_by_tx_out_index(txo_index))
            })
            .filter_map(Result::ok)
            .collect();

        // If we didn't find any of the tx_public_keys, then the transaction is either
        // still pending, or the inputs were spent in another transaction and
        // this transaction will never land.
        if found_pubkey_indices.is_empty() {
            // Verify that the key images are not anywhere else in the ledger.
            let key_image_in_ledger: Vec<bool> = key_images
                .iter()
                .map(|key_image| {
                    self.ledger_db.contains_key_image(key_image).map_err(|err| {
                        rpc_internal_error("ledger_db.contains_key_image", err, &self.logger)
                    })
                })
                .collect::<Result<Vec<bool>, RpcStatus>>()?;
            if key_image_in_ledger
                .iter()
                .any(|key_image_in_ledger| *key_image_in_ledger)
            {
                return Ok(api::GetTxStatusAsSenderResponse {
                    status: api::TxStatus::TransactionFailureKeyImageAlreadySpent.into(),
                });
            }

            // Otherwise, the transaction is still pending or otherwise status unknown.
            return Ok(api::GetTxStatusAsSenderResponse {
                status: api::TxStatus::Unknown.into(),
            });
        }

        // Verify that all block indices are the same value. If this fails, the receipt
        // is likely malformed, because it should be impossible to construct a
        // transaction containing output public keys that somehow end up landing
        // in different blocks.
        if found_pubkey_indices.iter().min() != found_pubkey_indices.iter().max() {
            return Ok(api::GetTxStatusAsSenderResponse {
                status: api::TxStatus::PublicKeysInDifferentBlocks.into(),
            });
        }

        // Get the block in which this transaction landed.
        let block_index = found_pubkey_indices[0];
        let block_contents = self
            .ledger_db
            .get_block_contents(block_index)
            .map_err(|err| rpc_internal_error("ledger_db.get_block_contents", err, &self.logger))?;

        // Convert key images to a list of booleans indicating whether they were found
        // in the block or not. All key_images from the same transaction should
        // land in the same block.
        let key_image_found: Vec<bool> = key_images
            .iter()
            .map(|key_image| block_contents.key_images.contains(key_image))
            .collect::<Vec<bool>>();

        // If all key images are in the block, the transaction was completed.
        if key_image_found
            .iter()
            .all(|key_image_found| *key_image_found)
        {
            return Ok(api::GetTxStatusAsSenderResponse {
                status: api::TxStatus::Verified.into(),
            });
        }

        // If only some key images found their way to the block, they were likely spent
        // from another transaction.
        if key_image_found
            .iter()
            .any(|key_image_found| *key_image_found)
        {
            return Ok(api::GetTxStatusAsSenderResponse {
                status: api::TxStatus::TransactionFailureKeyImageBlockMismatch.into(),
            });
        }

        // Check if the tombstone block was exceeded.
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        if num_blocks >= sender_tx_receipt.tombstone {
            return Ok(api::GetTxStatusAsSenderResponse {
                status: api::TxStatus::TombstoneBlockExceeded.into(),
            });
        }

        // No key images in ledger, tombstone block not yet exceeded.
        Ok(api::GetTxStatusAsSenderResponse {
            status: api::TxStatus::Unknown.into(),
        })
    }

    fn get_tx_status_as_receiver_impl(
        &mut self,
        request: api::GetTxStatusAsReceiverRequest,
    ) -> Result<api::GetTxStatusAsReceiverResponse, RpcStatus> {
        // Sanity-test the request.
        if request
            .receipt
            .as_ref()
            .unwrap_or(&Default::default())
            .tx_out_hash
            .len()
            != 32
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "receipt.tx_out_hash".into(),
            ));
        }

        if request
            .receipt
            .as_ref()
            .unwrap_or(&Default::default())
            .tombstone
            == 0
        {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "receipt.tombstone".into(),
            ));
        }

        // Check if the hash landed in the ledger.
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(
            &request
                .receipt
                .as_ref()
                .unwrap_or(&Default::default())
                .tx_out_hash,
        );

        match self.ledger_db.get_tx_out_index_by_hash(&hash_bytes) {
            Ok(_) => {
                // If a monitor ID was given then validate the confirmation number
                match request.monitor_id.len() {
                    0 => { /* no monitor ID given */ }
                    32 => {
                        let monitor_id =
                            MonitorId::try_from(&request.monitor_id).map_err(|err| {
                                rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger)
                            })?;

                        // Get monitor data for this monitor.
                        let monitor_data = self
                            .mobilecoind_db
                            .get_monitor_data(&monitor_id)
                            .map_err(|err| {
                                rpc_internal_error(
                                    "mobilecoind_db.get_monitor_data",
                                    err,
                                    &self.logger,
                                )
                            })?;
                        let tx_public_key = RistrettoPublic::try_from(
                            request
                                .receipt
                                .as_ref()
                                .unwrap_or(&Default::default())
                                .tx_public_key
                                .as_ref()
                                .unwrap_or(&Default::default()),
                        )
                        .map_err(|err| {
                            rpc_internal_error("RistrettoPublic.try_from", err, &self.logger)
                        })?;
                        let view_private_key = monitor_data.account_key.view_private_key();

                        if request
                            .receipt
                            .as_ref()
                            .unwrap_or(&Default::default())
                            .confirmation_number
                            .len()
                            != 32
                        {
                            return Err(RpcStatus::with_message(
                                RpcStatusCode::INVALID_ARGUMENT,
                                "receipt.confirmation_number".into(),
                            ));
                        }

                        // Test that the confirmation number is valid. Only the party constructing
                        // the transaction could have created the correct confirmation number.
                        let confirmation_number = {
                            let mut confirmation_bytes = [0u8; 32];
                            confirmation_bytes.copy_from_slice(
                                request
                                    .receipt
                                    .as_ref()
                                    .unwrap_or(&Default::default())
                                    .confirmation_number
                                    .as_slice(),
                            );
                            TxOutConfirmationNumber::from(confirmation_bytes)
                        };
                        if !confirmation_number.validate(&tx_public_key, view_private_key) {
                            // If the confirmation number is invalid, this means that the
                            // transaction did get added to the ledger
                            // but the party constructing the receipt failed
                            // to prove that they created it. This prevents a third-party observer
                            // from taking credit for someone elses
                            // payment.
                            return Ok(api::GetTxStatusAsReceiverResponse {
                                status: api::TxStatus::InvalidConfirmationNumber.into(),
                            });
                        }
                    }
                    _ => {
                        return Err(RpcStatus::with_message(
                            RpcStatusCode::INVALID_ARGUMENT,
                            "monitor_id".into(),
                        ));
                    }
                }

                // The hash found its way into the ledger, so the transaction succeeded.
                return Ok(api::GetTxStatusAsReceiverResponse {
                    status: api::TxStatus::Verified.into(),
                });
            }
            Err(mc_ledger_db::Error::NotFound) => {}
            Err(err) => {
                return Err(rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_hash",
                    err,
                    &self.logger,
                ));
            }
        };

        // Check if the tombstone block was exceeded.
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        if num_blocks
            >= request
                .receipt
                .as_ref()
                .unwrap_or(&Default::default())
                .tombstone
        {
            return Ok(api::GetTxStatusAsReceiverResponse {
                status: api::TxStatus::TombstoneBlockExceeded.into(),
            });
        }

        // Tx out not in ledger, tombstone block not yet exceeded.
        Ok(api::GetTxStatusAsReceiverResponse {
            status: api::TxStatus::Unknown.into(),
        })
    }

    fn get_processed_block_impl(
        &mut self,
        request: api::GetProcessedBlockRequest,
    ) -> Result<api::GetProcessedBlockResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // We will use the AccountKey to compute the Address Code
        let account_key = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?
            .account_key;

        // Get all processed block data for the requested block.
        let processed_tx_outs = self
            .mobilecoind_db
            .get_processed_block(&monitor_id, request.block)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_processed_block", err, &self.logger)
            })?
            .iter()
            .map(|src| {
                let subaddress = account_key.subaddress(src.subaddress_index);
                let wrapper = api::printable::PrintableWrapper {
                    wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                        (&subaddress).into(),
                    )),
                };
                let encoded = wrapper
                    .b58_encode()
                    .map_err(|err| rpc_internal_error("wrapper.b58_encode", err, &self.logger))?;
                Ok(api::ProcessedTxOut {
                    monitor_id: monitor_id.to_vec(),
                    subaddress_index: src.subaddress_index,
                    public_key: Some((&src.public_key).into()),
                    key_image: Some((&src.key_image).into()),
                    value: src.value,
                    direction: api::ProcessedTxOutDirection::from_i32(src.direction)
                        .unwrap_or(api::ProcessedTxOutDirection::Invalid)
                        .into(),
                    address_code: encoded,
                    token_id: src.token_id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Return response
        Ok(api::GetProcessedBlockResponse {
            tx_outs: processed_tx_outs,
        })
    }

    fn get_block_index_by_tx_pub_key_impl(
        &mut self,
        request: api::GetBlockIndexByTxPubKeyRequest,
    ) -> Result<api::GetBlockIndexByTxPubKeyResponse, RpcStatus> {
        let tx_public_key = RistrettoPublic::try_from(
            request
                .tx_public_key
                .as_ref()
                .unwrap_or(&Default::default()),
        )
        .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let compressed_tx_public_key = CompressedRistrettoPublic::from(&tx_public_key);

        let tx_out_index = self
            .ledger_db
            .get_tx_out_index_by_public_key(&compressed_tx_public_key)
            .map_err(|err| {
                rpc_internal_error(
                    "ledger_db.get_tx_out_index_by_public_key",
                    err,
                    &self.logger,
                )
            })?;

        let block_index = self
            .ledger_db
            .get_block_index_by_tx_out_index(tx_out_index)
            .map_err(|err| {
                rpc_internal_error(
                    "ledger_db.get_block_index_by_tx_out_index",
                    err,
                    &self.logger,
                )
            })?;

        Ok(api::GetBlockIndexByTxPubKeyResponse { block: block_index })
    }

    fn get_tx_out_results_by_pub_key_impl(
        &mut self,
        request: api::GetTxOutResultsByPubKeyRequest,
    ) -> Result<api::GetTxOutResultsByPubKeyResponse, RpcStatus> {
        let tx_out_pub_keys = request
            .tx_out_public_keys
            .iter()
            .map(CompressedRistrettoPublic::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| rpc_invalid_arg_error("tx_out_public_keys", err, &self.logger))?;

        let latest_block: mc_api::blockchain::Block = (&self
            .ledger_db
            .get_latest_block()
            .map_err(|err| rpc_internal_error("ledger_db.get_latest_block", err, &self.logger))?)
            .into();

        let results = tx_out_pub_keys
            .iter()
            .map(|pk| self.get_tx_out_result(pk))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| rpc_internal_error("get_tx_out_result", err, &self.logger))?;

        Ok(api::GetTxOutResultsByPubKeyResponse {
            results,
            latest_block: Some(latest_block),
        })
    }

    fn get_balance_impl(
        &mut self,
        request: api::GetBalanceRequest,
    ) -> Result<api::GetBalanceResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get all utxos for this monitor id.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, request.subaddress_index)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Sum them up.
        let balance = utxos
            .iter()
            // Filter only to the requested token id.
            .filter(|utxo| utxo.token_id == request.token_id)
            .map(|utxo| utxo.value as u128)
            .sum::<u128>();

        // It's possible the balance does not fit into a u64.
        if balance > u64::MAX.into() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                format!("balance of {balance} won't fit in u64, fetch utxo list instead"),
            ));
        }

        // Return response.
        Ok(api::GetBalanceResponse {
            balance: balance as u64,
        })
    }

    fn send_payment_impl(
        &mut self,
        request: api::SendPaymentRequest,
    ) -> Result<api::SendPaymentResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get monitor data for this monitor.
        let sender_monitor_data = self
            .mobilecoind_db
            .get_monitor_data(&sender_monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        // Get all utxos for this monitor id.
        let mut utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&sender_monitor_id, request.sender_subaddress)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Optionally filter for max value.
        if request.max_input_utxo_value > 0 {
            utxos.retain(|utxo| utxo.value <= request.max_input_utxo_value);
        }

        // Filter for requested token id.
        utxos.retain(|utxo| utxo.token_id == request.token_id);

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .outlay_list
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Set change address to sender address unless it has been overridden
        let change_subaddress = if request.override_change_subaddress {
            request.change_subaddress
        } else {
            request.sender_subaddress
        };

        // Get transaction memo builder.
        let transaction_memo =
            TransactionMemo::try_from(request.memo.as_ref().unwrap_or(&Default::default()))
                .map_err(|err| {
                    rpc_invalid_arg_error("transaction_memo.try_from", err, &self.logger)
                })?;
        let memo_builder = transaction_memo.memo_builder(&sender_monitor_data.account_key);

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                TokenId::from(request.token_id),
                change_subaddress,
                &utxos,
                &outlays,
                &self.get_last_block_infos(),
                request.fee,
                request.tombstone,
                memo_builder,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        let proto_tx_proposal = api::TxProposal::from(&tx_proposal);

        // Submit transaction.
        let submit_tx_request = api::SubmitTxRequest {
            tx_proposal: Some(proto_tx_proposal.clone()),
        };
        let submit_tx_response = self.submit_tx_impl(submit_tx_request)?;

        // Return response.
        Ok(api::SendPaymentResponse {
            sender_tx_receipt: submit_tx_response.sender_tx_receipt,
            receiver_tx_receipt_list: submit_tx_response.receiver_tx_receipt_list,
            tx_proposal: Some(proto_tx_proposal),
        })
    }

    fn pay_address_code_impl(
        &mut self,
        request: api::PayAddressCodeRequest,
    ) -> Result<api::SendPaymentResponse, RpcStatus> {
        // Sanity check.
        if request.amount == 0 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INVALID_ARGUMENT,
                "amount".into(),
            ));
        }

        // Try and decode the address code.
        let parse_address_code_request = api::ParseAddressCodeRequest {
            b58_code: request.receiver_b58_code.clone(),
        };
        let parse_address_code_response =
            self.parse_address_code_impl(parse_address_code_request)?;

        // Forward to SendPayment
        let outlay = api::Outlay {
            value: request.amount,
            receiver: parse_address_code_response.receiver,
            ..Default::default()
        };

        let send_payment_request = api::SendPaymentRequest {
            sender_monitor_id: request.sender_monitor_id,
            sender_subaddress: request.sender_subaddress,
            outlay_list: vec![outlay],
            fee: request.fee,
            tombstone: request.tombstone,
            max_input_utxo_value: request.max_input_utxo_value,
            override_change_subaddress: request.override_change_subaddress,
            change_subaddress: request.change_subaddress,
            token_id: request.token_id,
            ..Default::default()
        };

        self.send_payment_impl(send_payment_request)
    }

    fn get_network_status_impl(
        &mut self,
        _request: (),
    ) -> Result<api::GetNetworkStatusResponse, RpcStatus> {
        let network_state = self.network_state.read().expect("lock poisoned");
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;
        if num_blocks == 0 {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                "no bootstrap block".to_owned(),
            ));
        }
        let local_block_index = num_blocks - 1;

        // Get LastBlockInfo from our peers - this is the same code as
        // `self.get_last_block_infos` but avoids locking the same rwlock twice from the same thread (see potential deadlock scenario example in https://doc.rust-lang.org/std/sync/struct.RwLock.html).
        let block_infos = network_state
            .peer_to_block_info()
            .values()
            .cloned()
            .collect::<Vec<_>>();

        // choose the block info which is latest in terms of block index (we may be
        // isolated from some of the nodes)
        let last_block_info = block_infos
            .into_iter()
            .max_by_key(|info| info.block_index)
            .ok_or_else(|| {
                RpcStatus::with_message(RpcStatusCode::INTERNAL, "no peers reachable".to_owned())
            })?;

        let mcd_last_block_info = api::LastBlockInfo {
            index: last_block_info.block_index,
            mob_minimum_fee: last_block_info
                .minimum_fees
                .get(&TokenId::from(0))
                .cloned()
                .unwrap_or(0),
            minimum_fees: last_block_info
                .minimum_fees
                .into_iter()
                .map(|(token_id, fee)| (*token_id, fee))
                .collect(),
            network_block_version: last_block_info.network_block_version,
        };

        Ok(api::GetNetworkStatusResponse {
            network_highest_block_index: network_state
                .highest_block_index_on_network()
                .unwrap_or(0),
            peer_block_index_map: network_state
                .peer_to_current_block_index()
                .iter()
                .map(|(responder_id, block_index)| (responder_id.to_string(), *block_index))
                .collect(),
            local_block_index,
            is_behind: network_state.is_behind(local_block_index),
            last_block_info: Some(mcd_last_block_info),
            chain_id: self.chain_id.clone(),
        })
    }

    fn set_db_password_impl(
        &mut self,
        request: api::SetDbPasswordRequest,
    ) -> Result<(), RpcStatus> {
        // Check if the database is unlocked and allowing this operation.
        if !self.mobilecoind_db.is_unlocked() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                "must unlock before changing current password".to_owned(),
            ));
        }

        // Re-encrypt data using the new password.
        self.mobilecoind_db
            .re_encrypt(request.password.as_slice())
            .map_err(|err| rpc_internal_error("mobilecoind_db.re_encrypt", err, &self.logger))?;

        log::info!(self.logger, "DB encryption password updated successfully.");

        Ok(())
    }

    fn unlock_db_impl(&mut self, request: api::UnlockDbRequest) -> Result<(), RpcStatus> {
        if self.mobilecoind_db.is_unlocked() {
            return Err(RpcStatus::with_message(
                RpcStatusCode::INTERNAL,
                "already unlocked".to_owned(),
            ));
        }

        self.mobilecoind_db
            .check_and_store_password(request.password.as_slice())
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.check_and_store_password", err, &self.logger)
            })?;

        log::info!(self.logger, "Successfully unlocked, starting sync thread.");
        (self.start_sync_thread)();

        Ok(())
    }

    fn get_block_timestamp(&self, block_index: BlockIndex) -> (u64, TimestampResultCode) {
        self.watcher_db
            .as_ref()
            .and_then(|watcher| watcher.get_block_timestamp(block_index).ok())
            .unwrap_or((u64::MAX, TimestampResultCode::WatcherDatabaseError))
    }

    fn get_tx_out_result(
        &self,
        tx_out_pubkey: &CompressedRistrettoPublic,
    ) -> Result<TxOutResult, LedgerError> {
        let mut result = TxOutResult {
            tx_out_pubkey: Some(tx_out_pubkey.into()),
            ..Default::default()
        };

        let tx_out_index = match self.ledger_db.get_tx_out_index_by_public_key(tx_out_pubkey) {
            Ok(index) => index,
            Err(LedgerError::NotFound) => {
                result.result_code = TxOutResultCode::NotFound.into();
                return Ok(result);
            }
            Err(err) => {
                return Err(err);
            }
        };

        result.result_code = TxOutResultCode::Found.into();
        result.tx_out_global_index = tx_out_index;

        let block_index = match self.ledger_db.get_block_index_by_tx_out_index(tx_out_index) {
            Ok(index) => index,
            Err(err) => {
                log::error!(
                    self.logger,
                    "Unexpected error when getting block by tx out index {}: {}",
                    tx_out_index,
                    err
                );
                result.result_code = TxOutResultCode::DatabaseError.into();
                return Ok(result);
            }
        };

        let (timestamp, ts_result) = self.get_block_timestamp(block_index);

        result.block_index = block_index;
        result.timestamp = timestamp;
        result.timestamp_result_code = ts_result as u32;

        Ok(result)
    }
}

macro_rules! build_api {
    ($( $service_function_name:ident, $service_request_type:ty, $service_response_type:ty, $service_function_impl:ident $(,)?)+)
    =>
    (
        impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver> MobilecoindApi for ServiceApi<T, FPR> {
            $(
                fn $service_function_name(
                    &mut self,
                    ctx: RpcContext,
                    request: $service_request_type,
                    sink: UnarySink<$service_response_type>,
                ) {
                    let logger = rpc_logger(&ctx, &self.logger);
                    send_result(
                        ctx,
                        sink,
                        self.$service_function_impl(request),
                        &logger,
                    )
                }
            )+
        }
    );
}

build_api! {
    // Monitors
    add_monitor, api::AddMonitorRequest, api::AddMonitorResponse, add_monitor_impl,
    remove_monitor, api::RemoveMonitorRequest, (), remove_monitor_impl,
    get_monitor_list, (), api::GetMonitorListResponse, get_monitor_list_impl,
    get_monitor_status, api::GetMonitorStatusRequest, api::GetMonitorStatusResponse, get_monitor_status_impl,
    get_unspent_tx_out_list, api::GetUnspentTxOutListRequest, api::GetUnspentTxOutListResponse, get_unspent_tx_out_list_impl,
    get_all_unspent_tx_out, api::GetAllUnspentTxOutRequest, api::GetAllUnspentTxOutResponse, get_all_unspent_tx_out_impl,

    // Utilities
    generate_root_entropy, (), api::GenerateRootEntropyResponse, generate_root_entropy_impl,
    generate_mnemonic, (), api::GenerateMnemonicResponse, generate_mnemonic_impl,
    get_account_key_from_root_entropy, api::GetAccountKeyFromRootEntropyRequest, api::GetAccountKeyResponse, get_account_key_from_root_entropy_impl,
    get_account_key_from_mnemonic, api::GetAccountKeyFromMnemonicRequest, api::GetAccountKeyResponse, get_account_key_from_mnemonic_impl,
    get_public_address, api::GetPublicAddressRequest, api::GetPublicAddressResponse, get_public_address_impl,
    get_short_address_hash, api::GetShortAddressHashRequest, api::GetShortAddressHashResponse, get_short_address_hash_impl,
    validate_authenticated_sender_memo, api::ValidateAuthenticatedSenderMemoRequest, api::ValidateAuthenticatedSenderMemoResponse, validate_authenticated_sender_memo_impl,
    tx_out_view_key_match, api::TxOutViewKeyMatchRequest, api::TxOutViewKeyMatchResponse, tx_out_view_key_match_impl,

    // b58 codes
    parse_request_code, api::ParseRequestCodeRequest, api::ParseRequestCodeResponse, parse_request_code_impl,
    create_request_code, api::CreateRequestCodeRequest, api::CreateRequestCodeResponse, create_request_code_impl,
    parse_transfer_code, api::ParseTransferCodeRequest, api::ParseTransferCodeResponse, parse_transfer_code_impl,
    create_transfer_code, api::CreateTransferCodeRequest, api::CreateTransferCodeResponse, create_transfer_code_impl,
    parse_address_code, api::ParseAddressCodeRequest, api::ParseAddressCodeResponse, parse_address_code_impl,
    create_address_code, api::CreateAddressCodeRequest, api::CreateAddressCodeResponse, create_address_code_impl,

    // Transactions
    get_mixins, api::GetMixinsRequest, api::GetMixinsResponse, get_mixins_impl,
    get_membership_proofs, api::GetMembershipProofsRequest, api::GetMembershipProofsResponse, get_membership_proofs_impl,
    generate_tx, api::GenerateTxRequest, api::GenerateTxResponse, generate_tx_impl,
    generate_optimization_tx, api::GenerateOptimizationTxRequest, api::GenerateOptimizationTxResponse, generate_optimization_tx_impl,
    generate_transfer_code_tx, api::GenerateTransferCodeTxRequest, api::GenerateTransferCodeTxResponse, generate_transfer_code_tx_impl,
    generate_tx_from_tx_out_list, api::GenerateTxFromTxOutListRequest, api::GenerateTxFromTxOutListResponse, generate_tx_from_tx_out_list_impl,
    generate_burn_redemption_tx, api::GenerateBurnRedemptionTxRequest, api::GenerateBurnRedemptionTxResponse, generate_burn_redemption_tx_impl,
    submit_tx, api::SubmitTxRequest, api::SubmitTxResponse, submit_tx_impl,

    // Signed contingent inputs
    generate_swap, api::GenerateSwapRequest, api::GenerateSwapResponse, generate_swap_impl,
    generate_mixed_tx, api::GenerateMixedTxRequest, api::GenerateMixedTxResponse, generate_mixed_tx_impl,

    // Databases
    get_ledger_info, (), api::GetLedgerInfoResponse, get_ledger_info_impl,
    get_block_info, api::GetBlockInfoRequest, api::GetBlockInfoResponse, get_block_info_impl,
    get_block, api::GetBlockRequest, api::GetBlockResponse, get_block_impl,
    get_latest_block, (), api::GetBlockResponse, get_latest_block_impl,
    get_blocks_data, api::GetBlocksDataRequest, api::GetBlocksDataResponse, get_blocks_data_impl,
    get_tx_status_as_sender, api::SubmitTxResponse, api::GetTxStatusAsSenderResponse, get_tx_status_as_sender_impl,
    get_tx_status_as_receiver, api::GetTxStatusAsReceiverRequest, api::GetTxStatusAsReceiverResponse, get_tx_status_as_receiver_impl,
    get_processed_block, api::GetProcessedBlockRequest, api::GetProcessedBlockResponse, get_processed_block_impl,
    get_block_index_by_tx_pub_key, api::GetBlockIndexByTxPubKeyRequest, api::GetBlockIndexByTxPubKeyResponse, get_block_index_by_tx_pub_key_impl,
    get_tx_out_results_by_pub_key, api::GetTxOutResultsByPubKeyRequest, api::GetTxOutResultsByPubKeyResponse, get_tx_out_results_by_pub_key_impl,

    // Convenience calls
    get_balance, api::GetBalanceRequest, api::GetBalanceResponse, get_balance_impl,
    send_payment, api::SendPaymentRequest, api::SendPaymentResponse, send_payment_impl,
    pay_address_code, api::PayAddressCodeRequest, api::SendPaymentResponse, pay_address_code_impl,

    // Network status
    get_network_status, (), api::GetNetworkStatusResponse, get_network_status_impl,

    // Database encryption
    set_db_password, api::SetDbPasswordRequest, (), set_db_password_impl,
    unlock_db, api::UnlockDbRequest, (), unlock_db_impl,

    get_version, (), api::MobilecoindVersionResponse, get_version_impl,
}

#[cfg(test)]
#[allow(clippy::needless_collect, deprecated)]
mod test {
    use super::*;
    use crate::{
        payments::DEFAULT_NEW_TX_BLOCK_ATTEMPTS,
        subaddress_store::SubaddressSPKId,
        test_utils::{
            self, add_block_to_ledger, add_txos_to_ledger, create_tx_out, get_test_fee_map,
            get_testing_environment, wait_for_monitors, DEFAULT_PER_RECIPIENT_AMOUNT,
        },
    };
    use grpcio::Error as GrpcError;
    use mc_account_keys::burn_address_view_private;
    use mc_blockchain_types::{Block, BlockVersion};
    use mc_common::{logger::test_with_logger, HashSet};
    use mc_fog_report_validation::{FullyValidatedFogPubkey, MockFogPubkeyResolver};
    use mc_ledger_db::test_utils::add_txos_and_key_images_to_ledger;
    use mc_mobilecoind_api::{decoded_memo, transaction_memo_rth};
    use mc_rand::RngCore;
    use mc_transaction_builder::{MemoBuilder, RTHMemoBuilder};
    use mc_transaction_core::{
        constants::{MAX_INPUTS, RING_SIZE},
        encrypted_fog_hint::EncryptedFogHint,
        fog_hint::FogHint,
        onetime_keys::recover_public_subaddress_spend_key,
        tokens::Mob,
        tx::Tx,
        CompressedCommitment, EncryptedMemo, MaskedAmount, MaskedAmountV2, Token,
    };
    use mc_transaction_extra::{SenderMemoCredential, SignedContingentInput};
    use mc_util_repr_bytes::{typenum::U32, GenericArray, ReprBytes};
    use mc_util_uri::FogUri;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{assert_matches::assert_matches, str::FromStr};

    const BLOCK_VERSION: BlockVersion = BlockVersion::MAX;

    #[test_with_logger]
    fn test_add_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        // Three random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger.clone(), &mut rng);

        // Create request for adding a new monitor.
        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            DEFAULT_SUBADDRESS_INDEX, // first_subaddress
            1,                        // num_subaddresses
            0,                        // first_block
            "",                       // name
        )
        .expect("failed to create data");

        let request = api::AddMonitorRequest {
            account_key: Some(mc_api::external::AccountKey::from(&data.account_key)),
            first_subaddress: data.first_subaddress,
            num_subaddresses: data.num_subaddresses,
            first_block: data.first_block,
            ..Default::default()
        };

        // Send request.
        let response = client.add_monitor(&request).expect("failed to add monitor");

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Compare the MonitorId we got back to the value we expected.
        let monitor_id = MonitorId::try_from(&response.monitor_id)
            .expect("failed to convert response to MonitorId");
        let expected_monitor_id = MonitorId::from(&data);

        assert_eq!(expected_monitor_id, monitor_id);

        // Check that the monitor is reported as new
        assert!(response.is_new);

        // Add the same monitor again
        let repeated_response = client.add_monitor(&request).expect("failed to add monitor");

        // Compare the MonitorId we got back to the value we expected.
        let repeated_monitor_id = MonitorId::try_from(&repeated_response.monitor_id)
            .expect("failed to convert repeated_response to MonitorId");

        assert_eq!(expected_monitor_id, repeated_monitor_id);

        // Check that the monitor is not reported as new
        assert!(!repeated_response.is_new);
    }

    #[test_with_logger]
    fn test_remove_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([22u8; 32]);

        // 10 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 10, &[], &[], logger, &mut rng);

        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());

        // Add some monitors directly to the database.
        let monitors_to_add = 10;
        let monitor_ids: Vec<MonitorId> = (0..monitors_to_add)
            .map(|_i| {
                let data = MonitorData::new(
                    AccountKey::random(&mut rng),
                    DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                    1,                        // num_subaddresses
                    0,                        // first_block
                    "",                       // name
                )
                .unwrap();
                mobilecoind_db.add_monitor(&data).unwrap()
            })
            .collect();

        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(monitors_to_add, monitors_map.len());

        // Remove all the monitors we added.
        for id in monitor_ids {
            let request = api::RemoveMonitorRequest {
                monitor_id: id.to_vec(),
            };
            client
                .remove_monitor(&request)
                .unwrap_or_else(|_| panic!("failed to remove monitor {id}"));
        }

        // Check that no monitors remain.
        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());
    }

    #[test_with_logger]
    fn test_get_monitor_list_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([21u8; 32]);

        // 10 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 10, &[], &[], logger.clone(), &mut rng);

        // Add some new monitors directly to the database.
        let monitors_to_add = 10;
        let monitor_ids: Vec<MonitorId> = (0..monitors_to_add)
            .map(|_i| {
                let data = MonitorData::new(
                    AccountKey::random(&mut rng),
                    DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                    1,                        // num_subaddresses
                    0,                        // first_block
                    "",                       // name
                )
                .unwrap();
                let id = mobilecoind_db.add_monitor(&data).unwrap();
                log::debug!(logger, "adding monitor {}", id,);
                id
            })
            .collect();

        // Ask the api for a list of all monitors.
        let response = client
            .get_monitor_list(&())
            .expect("failed to get monitor list");

        let monitor_id_list: Vec<MonitorId> = response
            .monitor_id_list
            .iter()
            .map(|bytes| {
                let id =
                    MonitorId::try_from(bytes).expect("failed to convert response to MonitorId");
                log::debug!(logger, "found monitor {}", id,);
                id
            })
            .collect();

        // Check monitor count.
        assert_eq!(monitors_to_add, monitor_id_list.len());

        // Check that all new monitors are present.
        assert_eq!(
            HashSet::from_iter(monitor_id_list.iter()),
            HashSet::from_iter(monitor_ids.iter()),
        );
    }

    #[test_with_logger]
    fn test_get_monitor_status_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // 10 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 10, &[], &[], logger.clone(), &mut rng);

        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            10, // first_subaddress
            20, // num_subaddresses
            30, // first_block
            "", // name
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query monitor status.
        let request = api::GetMonitorStatusRequest {
            monitor_id: id.to_vec(),
        };

        let response = client
            .get_monitor_status(&request)
            .expect("failed to get monitor status");
        let status = response.status.as_ref().expect("no status in response");

        // Verify the data we got matches what we expected
        assert_eq!(
            data.account_key,
            AccountKey::try_from(status.account_key.as_ref().unwrap()).unwrap(),
        );
        assert_eq!(status.first_subaddress, data.first_subaddress);
        assert_eq!(status.num_subaddresses, data.num_subaddresses);
        assert_eq!(status.first_block, data.first_block);
        assert_eq!(status.next_block, data.next_block);

        // Calling get_monitor_status for nonexistent or invalid monitor_id should
        // return an error.
        mobilecoind_db.remove_monitor(&id).unwrap();

        let request = api::GetMonitorStatusRequest {
            monitor_id: id.to_vec(),
        };
        assert!(client.get_monitor_status(&request).is_err());

        let request = api::GetMonitorStatusRequest::default();
        assert!(client.get_monitor_status(&request).is_err());

        let request = api::GetMonitorStatusRequest {
            monitor_id: vec![3; 3],
        };
        assert!(client.get_monitor_status(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_unspent_tx_out_list_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[account_key.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &vec![
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                account_key.default_subaddress(),
            ],
            Amount::new(1000, 2.into()),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query for unspent tx outs for a subaddress that did not receive any tx outs.
        let request = api::GetUnspentTxOutListRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 1,
            ..Default::default()
        };

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        assert_eq!(response.output_list.to_vec(), vec![]);

        // Query with the correct subaddress index.
        let mut request = api::GetUnspentTxOutListRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        let utxos: Vec<UnspentTxOut> = response
            .output_list
            .iter()
            .map(|proto_utxo| {
                UnspentTxOut::try_from(proto_utxo).expect("failed converting proto utxo")
            })
            .collect();

        // Verify the data we got matches what we expected. This assumes knowledge about
        // how the test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().unwrap();
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let expected_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .map(|tx_out| {
                let (amount, _) = tx_out
                    .view_key_match(account_key.view_private_key())
                    .unwrap();

                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(0),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: 0,
                    key_image,
                    value: amount.value,
                    token_id: *amount.token_id,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                    memo_payload: MemoPayload::default().into(),
                }
            })
            .collect();

        // Compare - we should have one less utxo than number of blocks, since the last
        // one we added is a different token id.
        assert_eq!(utxos.len(), num_blocks as usize - 1);
        assert_eq!(
            HashSet::from_iter(utxos.iter()),
            HashSet::from_iter(
                expected_utxos
                    .iter()
                    .filter(|utxo| utxo.token_id == *Mob::ID)
            )
        );

        // Try with the non-MOB token id.
        request.token_id = 2;
        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        let utxos: Vec<UnspentTxOut> = response
            .output_list
            .iter()
            .map(|proto_utxo| {
                UnspentTxOut::try_from(proto_utxo).expect("failed converting proto utxo")
            })
            .collect();

        assert_eq!(utxos.len(), 1);
        assert_eq!(
            HashSet::from_iter(utxos.iter()),
            HashSet::from_iter(expected_utxos.iter().filter(|utxo| utxo.token_id == 2))
        );
    }

    #[test_with_logger]
    fn test_get_all_unspent_tx_out_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[account_key.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &vec![
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                account_key.default_subaddress(),
            ],
            Amount::new(1000, 2.into()),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Add a block with a non-MOB token ID, to an off subaddress
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &vec![
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                account_key.subaddress(1),
            ],
            Amount::new(1000, 2.into()),
            &[KeyImage::from(102)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query with the known id
        let request = api::GetAllUnspentTxOutRequest {
            monitor_id: id.to_vec(),
        };

        let response = client
            .get_all_unspent_tx_out(&request)
            .expect("failed to get all unspent tx out");

        let utxos: Vec<UnspentTxOut> = response
            .output_list
            .iter()
            .map(|proto_utxo| {
                UnspentTxOut::try_from(proto_utxo).expect("failed converting proto utxo")
            })
            .collect();

        // Verify the data we got matches what we expected. This assumes knowledge about
        // how the test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().unwrap();
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let expected_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .enumerate()
            .map(|(idx, tx_out)| {
                let (amount, _) = tx_out
                    .view_key_match(account_key.view_private_key())
                    .unwrap();

                // Get the expected subaddress index, based on block index. Everything is on 0
                // except in the last block, where we used subaddrss 1.
                let subaddress_index = if idx as u64 == num_blocks - 1 { 1 } else { 0 };

                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(subaddress_index),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index,
                    key_image,
                    value: amount.value,
                    token_id: *amount.token_id,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                    memo_payload: MemoPayload::default().into(),
                }
            })
            .collect();

        // Compare - we should have one utxo in each block.
        assert_eq!(utxos.len(), num_blocks as usize);
        assert_eq!(
            HashSet::from_iter(utxos.iter()),
            HashSet::from_iter(expected_utxos.iter())
        );
    }

    #[test_with_logger]
    fn test_generate_root_entropy_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // call get entropy
        let response = client.generate_root_entropy(&()).unwrap();
        let entropy = response.root_entropy;
        assert_eq!(entropy.len(), 32);
        assert_ne!(entropy, vec![0; 32]);
    }

    #[test_with_logger]
    fn test_generate_mnemonic_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // call get entropy
        let response = client.generate_mnemonic(&()).unwrap();
        let mnemonic_str = &response.mnemonic;
        assert_ne!(mnemonic_str, "");

        // Should be a valid mnemonic.
        let mnemonic =
            Mnemonic::from_phrase(mnemonic_str, Language::English).expect("invalid mnemonic_str");
        assert_eq!(mnemonic.entropy().len(), 32);

        assert_eq!(mnemonic.entropy(), response.bip39_entropy);
    }

    #[test_with_logger]
    fn test_get_account_key_from_mnemonic_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Use mnemonic to construct AccountKey.
        let mnemonic_str =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let expected_account_key = {
            let mnemonic =
                Mnemonic::from_phrase(mnemonic_str, Language::English).expect("from_phrase failed");
            let key = mnemonic.derive_slip10_key(666);
            AccountKey::from(key)
        };

        let request = api::GetAccountKeyFromMnemonicRequest {
            mnemonic: mnemonic_str.to_string(),
            account_index: 666,
        };

        let response = client.get_account_key_from_mnemonic(&request).unwrap();

        assert_eq!(
            expected_account_key,
            AccountKey::try_from(response.account_key.as_ref().unwrap()).unwrap(),
        );

        // Calling with no mnemonic or invalid mnemonic should error.
        let request = api::GetAccountKeyFromMnemonicRequest::default();
        assert!(client.get_account_key_from_mnemonic(&request).is_err());

        let request = api::GetAccountKeyFromMnemonicRequest {
            mnemonic: "lol".to_string(),
            ..Default::default()
        };
        assert!(client.get_account_key_from_mnemonic(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_account_key_from_root_entropy_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Use root entropy to construct AccountKey.
        let root_entropy = [123u8; 32];
        let root_id = RootIdentity::from(&root_entropy);
        let account_key = AccountKey::from(&root_id);

        let request = api::GetAccountKeyFromRootEntropyRequest {
            root_entropy: root_entropy.to_vec(),
        };

        let response = client.get_account_key_from_root_entropy(&request).unwrap();

        assert_eq!(
            account_key,
            AccountKey::try_from(response.account_key.as_ref().unwrap()).unwrap(),
        );

        // Calling with no root entropy or invalid root entropy should error.
        let request = api::GetAccountKeyFromRootEntropyRequest::default();
        assert!(client.get_account_key_from_root_entropy(&request).is_err());

        let root_entropy = [123u8; 31];
        let request = api::GetAccountKeyFromRootEntropyRequest {
            root_entropy: root_entropy.to_vec(),
        };
        assert!(client.get_account_key_from_root_entropy(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_public_address_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);
        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            10, // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Call get public address.
        let request = api::GetPublicAddressRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 10,
        };
        let response = client.get_public_address(&request).unwrap();

        assert_eq!(
            PublicAddress::try_from(response.public_address.as_ref().unwrap()).unwrap(),
            account_key.subaddress(10)
        );

        // Test that the b58 encoding is correct
        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&account_key.subaddress(10)).into(),
            )),
        };
        let b58_code = wrapper.b58_encode().unwrap();
        assert_eq!(response.b58_code, b58_code,);

        // Subaddress that is out of index or an invalid monitor id should error.
        let request = api::GetPublicAddressRequest::default();
        assert!(client.get_public_address(&request).is_err());

        let request = api::GetPublicAddressRequest {
            monitor_id: vec![3; 3],
            subaddress_index: 10,
        };
        assert!(client.get_public_address(&request).is_err());

        let request = api::GetPublicAddressRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 0,
        };
        assert!(client.get_public_address(&request).is_err());

        let request = api::GetPublicAddressRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 1000,
        };
        assert!(client.get_public_address(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_short_address_hash_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([57u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        let account_key = AccountKey::random(&mut rng);
        let public_address = account_key.default_subaddress();

        // Try to compute the short address hash
        let mut request = api::GetShortAddressHashRequest::default();
        // Check that an invalid request returns an error
        assert!(client.get_short_address_hash(&request).is_err());

        request.public_address = Some((&public_address).into());
        let response = client.get_short_address_hash(&request).unwrap();

        // Test that the short address hash is correct
        let hash = ShortAddressHash::from(&public_address);
        assert_eq!(&response.hash[..], hash.as_ref());
    }

    #[test_with_logger]
    fn test_validate_authenticated_sender_memo_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([57u8; 32]);
        // In this test, Bob is a mobilecoind user,
        // who gets a TxOut from alice with a sender memo with payment request id
        let bob_account_key = AccountKey::random(&mut rng);
        let bob_addr = bob_account_key.subaddress(10);
        let data = MonitorData::new(
            bob_account_key.clone(),
            10, // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger.clone(), &mut rng);

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // This is alice
        let alice_account_key = AccountKey::random(&mut rng);
        let alice_addr = alice_account_key.default_subaddress();
        let alice_cred = SenderMemoCredential::from(&alice_account_key);
        let alice_hash = ShortAddressHash::from(&alice_addr);

        // Alice makes a TxOut for Bob, with an authenticated sender memo for her
        // default subaddress
        let amount = Amount::new(5000000, 0.into());

        let e_fog_hint = EncryptedFogHint::fake_onetime_hint(&mut rng);

        // Use RTH memo builder to write a sender memo with payment request id
        let mut memo_builder = RTHMemoBuilder::default();
        memo_builder.set_sender_credential(alice_cred);
        memo_builder.set_payment_request_id(99);

        let memo_tx_out = TxOut::new_with_memo(
            BLOCK_VERSION,
            amount,
            &bob_addr,
            &FromRandom::from_random(&mut rng),
            e_fog_hint,
            |memo_ctxt| memo_builder.make_memo_for_output(amount, &bob_addr, memo_ctxt),
        )
        .unwrap();

        // Alice adds the TxOut to the ledger
        add_txos_to_ledger(&mut ledger_db, BLOCK_VERSION, &[memo_tx_out], &mut rng).unwrap();

        // Allow the monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Bob should find the UTXO
        let request = api::GetUnspentTxOutListRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 10,
            ..Default::default()
        };
        let response = client.get_unspent_tx_out_list(&request).unwrap();

        assert_eq!(response.output_list.len(), 1);
        let utxo = &response.output_list[0];

        // The utxo details should be as expected
        assert_eq!(utxo.value, 5000000);
        assert_eq!(utxo.token_id, 0);
        assert_eq!(utxo.subaddress_index, 10);
        // The utxo should have a memo payload
        assert_eq!(utxo.memo_payload.len(), 66);

        // The utxo should have been decoded successfully
        let decoded = utxo
            .decoded_memo
            .as_ref()
            .unwrap()
            .decoded_memo
            .as_ref()
            .unwrap();
        match decoded {
            decoded_memo::DecodedMemo::AuthenticatedSenderMemo(asm) => {
                // The details should match to alice's hash and have a payment request id
                assert_eq!(asm.sender_hash, alice_hash.as_ref());
                assert_eq!(asm.payment_request_id, Some(99));
                assert_eq!(asm.payment_intent_id, None);
            }
            _ => panic!("Unexpected memo type"),
        }

        // If we go fetch Alice's address via her hash, we should be able to validate
        // the memo.
        let mut request = api::ValidateAuthenticatedSenderMemoRequest {
            monitor_id: id.to_vec(),
            utxo: Some(utxo.clone()),
            sender: Some((&alice_addr).into()),
        };

        let response = client.validate_authenticated_sender_memo(&request).unwrap();
        assert!(response.success);

        // If we don't use the right address during validation, then validation should
        // fail
        request.sender = Some((&bob_addr).into());
        let response = client.validate_authenticated_sender_memo(&request).unwrap();
        assert!(!response.success);
    }

    #[test_with_logger]
    fn test_tx_out_view_key_match_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Insert a block with a known recipient (this is block 4)
        let recipient = AccountKey::random(&mut rng);
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &[recipient.default_subaddress()],
            Amount::new(102030, TokenId::from(1)),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Get the block so we can test the matching.
        let block = client
            .get_block(&api::GetBlockRequest {
                block: ledger_db.num_blocks().unwrap() - 1,
            })
            .unwrap();

        // The block should have a single tx out and we should be able to match it with
        // the correct view private key.
        let view_private_key =
            mc_api::external::RistrettoPrivate::from(recipient.view_private_key());
        let resp = client
            .tx_out_view_key_match(&api::TxOutViewKeyMatchRequest {
                txo: Some(block.txos[0].clone()),
                view_private_key: Some(view_private_key),
            })
            .unwrap();

        assert!(resp.matched);
        assert_eq!(resp.value, 102030);
        assert_eq!(resp.token_id, 1);
        assert_eq!(resp.shared_secret.unwrap().data.len(), 32);

        // Try with an incorrect view private key
        let view_private_key = mc_api::external::RistrettoPrivate::from(
            AccountKey::random(&mut rng).view_private_key(),
        );
        let resp = client
            .tx_out_view_key_match(&api::TxOutViewKeyMatchRequest {
                txo: Some(block.txos[0].clone()),
                view_private_key: Some(view_private_key),
            })
            .unwrap();

        assert!(!resp.matched);
        assert_eq!(resp.value, 0);
        assert_eq!(resp.token_id, 0);
        assert_eq!(
            resp.shared_secret
                .as_ref()
                .unwrap_or(&Default::default())
                .data
                .len(),
            0
        );
    }

    #[test_with_logger]
    fn test_vectors_validate_authenticated_sender_memo_impl(logger: Logger) {
        // In this test, we take an actual TxOut generated by signal, at block version
        // 3, sent to a full-service account, and confirm that mobilecoind can
        // also find the TxOut and validate the memo.

        // no known recipient, 3 random recipients and no monitors.
        let mut rng: StdRng = SeedableRng::from_seed([93u8; 32]);
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BlockVersion::THREE, 3, &[], &[], logger.clone(), &mut rng);

        let request = api::GetAccountKeyFromMnemonicRequest {
            mnemonic: "veteran leaf business lounge rocket prepare endorse town text reject nothing fuel earn solid want drum clog flip entire icon swallow birth loyal return".to_owned(),
            ..Default::default()
        };
        let response = client.get_account_key_from_mnemonic(&request).unwrap();

        let account_key = AccountKey::try_from(response.account_key.as_ref().unwrap()).unwrap();

        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            2,  // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Construct the test TxOut
        let tx_out = TxOut {
            public_key: CompressedRistrettoPublic::try_from(&hex::decode("026279e22d00e163a9edd28506dbe778752ed53a5cc5625d5d712b3f371d8f1f").unwrap()[..]).unwrap(),
            target_key: CompressedRistrettoPublic::try_from(&hex::decode("5cf12e056b9131692405f410cc03049b49d6e2d12b05c3be8f9504fbe2ba9d48").unwrap()[..]).unwrap(),
            e_fog_hint: EncryptedFogHint::try_from(&hex::decode("725539d655e35bf2ffbbb21aa056da02da8a2f36a9014cb9c474fb2573ed4c972e0964dc03fdff12b46dd1c0bbe4d341c8d4a42f6b09782fb3b5d93e1116b1bb9f65d205af9328fb0a5b8f3347626f7ebc4e0100").unwrap()[..]).unwrap(),
            e_memo: Some(EncryptedMemo::try_from(&hex::decode("c4277d6a49b752fd39666d1317216e41d8f0bc6ed2d74fc06f36c9f07b6d9954c26d2ce7c3ff4aa95dc1c2e26f50e025d57534258a327f6c5ddd3916acdfa174e2f3").unwrap()[..]).unwrap()),
            masked_amount: Some(MaskedAmount::V2(MaskedAmountV2 {
                commitment: CompressedCommitment::try_from(&hex::decode("42ff4c72f8b4c02e0ccba20b0197fa19e33522b131c243a7df9660639f1e4949").unwrap()[..]).unwrap(),
                masked_value: 9333989940299914976,
                masked_token_id: hex::decode("be23706fb90b5bfb").unwrap()
            }))
        };

        // Add the TxOut to the ledger
        add_txos_to_ledger(&mut ledger_db, BLOCK_VERSION, &[tx_out], &mut rng).unwrap();

        // Allow the monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Bob should find the UTXO
        let request = api::GetUnspentTxOutListRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };
        let response = client.get_unspent_tx_out_list(&request).unwrap();

        assert_eq!(response.output_list.len(), 1);
        let utxo = &response.output_list[0];

        // The utxo details should be as expected
        assert_eq!(utxo.value, 1000000000);
        assert_eq!(utxo.token_id, 0);
        assert_eq!(utxo.subaddress_index, 0);
        // The utxo should have a memo payload
        assert_eq!(utxo.memo_payload.len(), 66);

        // The utxo should have been decoded successfully
        let decoded = utxo
            .decoded_memo
            .as_ref()
            .unwrap()
            .decoded_memo
            .as_ref()
            .unwrap();
        match decoded {
            decoded_memo::DecodedMemo::AuthenticatedSenderMemo(asm) => {
                // The details should have no payment request / intent id's
                assert_eq!(asm.payment_request_id, None);
                assert_eq!(asm.payment_intent_id, None);

                // The short hash should match the expected value
                // Get public address and hash from the b58 address
                let sender_b58 = "WZKU1isCc7HUrNgpugWZaUhfLnsxsL3w3s3KaTu8AkwtCjqt9AEpWh3TNhG9dXjAKkL8qRput4paEeCAMS4PJ2E6r44ysPgMiStkjq2ons6GLaQqtVpYZQzxsbsLAtPkpXhKnxyjfHZxtD3CExzxxGUpnmZNjvdVJh1nByZaJ7pjhdPK81haNPqL7Kv7tk9m9A9segvmyZjzjkvFuHYrnWjgMwsfGpkkhtHz8yp3ftrUs";

                let request = api::ParseAddressCodeRequest {
                    b58_code: sender_b58.to_owned(),
                };
                let response = client.parse_address_code(&request).unwrap();
                let public_address = response.receiver.unwrap();

                let request = api::GetShortAddressHashRequest {
                    public_address: Some(public_address.clone()),
                };
                let response = client.get_short_address_hash(&request).unwrap();
                let expected_hash = response.hash;

                assert_eq!(asm.sender_hash, expected_hash);

                // If we go fetch Alice's address via her hash, we should be able to validate
                // the memo.
                let request = api::ValidateAuthenticatedSenderMemoRequest {
                    monitor_id: id.to_vec(),
                    utxo: Some(utxo.clone()),
                    sender: Some(public_address.clone()),
                };

                let response = client.validate_authenticated_sender_memo(&request).unwrap();
                assert!(response.success);
            }
            _ => {
                panic!("Expected AuthenticatedSenderMemo");
            }
        }
    }

    #[test_with_logger]
    fn test_get_ledger_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Call get ledger info.
        let response = client.get_ledger_info(&()).unwrap();
        assert_eq!(response.block_count, ledger_db.num_blocks().unwrap());
        assert_eq!(response.txo_count, ledger_db.num_txos().unwrap());
    }

    #[test_with_logger]
    fn test_get_block_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Call get block info for a valid block.
        let request = api::GetBlockInfoRequest { block: 0 };

        let response = client.get_block_info(&request).unwrap();
        assert_eq!(response.key_image_count, 0); // test code does not generate any key images
        assert_eq!(response.txo_count, 3); // 3 recipients = 3 tx outs

        // Call with an invalid block number.
        let request = api::GetBlockInfoRequest {
            block: ledger_db.num_blocks().unwrap(),
        };
        assert!(client.get_block_info(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_block_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Call get block info for a valid block.
        let request = api::GetBlockRequest { block: 0 };

        let response = client.get_block(&request).unwrap();
        assert_eq!(
            Block::try_from(response.block.as_ref().unwrap()).unwrap(),
            ledger_db.get_block(0).unwrap()
        );
        // FIXME: Implement block signatures for mobilecoind and test
        assert_eq!(response.txos.len(), 3); // 3 recipients = 3 tx outs
        assert_eq!(response.key_images.len(), 0); // test code does not generate
                                                  // any key images
        assert_eq!(
            response.timestamp_result_code(),
            mc_api::watcher::TimestampResultCode::WatcherDatabaseError
        ); // test code doesnt have a watcher
    }

    #[test_with_logger]
    fn test_get_latest_block_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Call get latet block
        let response = client.get_latest_block(&Default::default()).unwrap();

        assert_eq!(
            Block::try_from(response.block.as_ref().unwrap()).unwrap(),
            ledger_db.get_latest_block().unwrap(),
        );
        // FIXME: Implement block signatures for mobilecoind and test
        assert_eq!(response.txos.len(), 3); // 3 recipients = 3 tx outs
        assert_eq!(response.key_images.len(), 1);
        assert_eq!(
            response.timestamp_result_code(),
            mc_api::watcher::TimestampResultCode::WatcherDatabaseError
        ); // test code doesnt have a watcher
    }

    #[test_with_logger]
    fn test_get_blocks_data(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Call get block data
        let request = api::GetBlocksDataRequest {
            blocks: vec![0, 2, 100, 1],
        };

        let response = client.get_blocks_data(&request).unwrap();
        assert_eq!(
            Block::try_from(response.latest_block.as_ref().unwrap()).unwrap(),
            ledger_db.get_latest_block().unwrap()
        );

        let blocks = response.results;
        assert_eq!(blocks.len(), 4);
        assert!(blocks[0].found);
        assert!(blocks[1].found);
        assert!(!blocks[2].found);
        assert!(blocks[3].found);

        assert_eq!(
            blocks.iter().map(|b| b.block_index).collect::<Vec<_>>(),
            request.blocks
        );

        assert_eq!(
            blocks[0].block_data.as_ref().unwrap(),
            &ArchiveBlock::from(&ledger_db.get_block_data(0).unwrap())
        );
    }

    #[test_with_logger]
    fn test_get_tx_status_as_sender_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Insert a block with some key images in it.
        let recipient = AccountKey::random(&mut rng).default_subaddress();
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &[recipient.clone()],
            Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
            &[KeyImage::from(1), KeyImage::from(2), KeyImage::from(3)],
            &mut rng,
        )
        .unwrap();

        // Create receiver_tx_receipt based on the txout created in
        // add_block_to_ledger
        let block = ledger_db
            .get_block_contents(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let output = block.outputs[0].clone();

        let mut receiver_receipt = api::ReceiverTxReceipt {
            recipient: Some(api::external::PublicAddress::from(&recipient)),
            tx_public_key: Some(api::external::CompressedRistretto::from(&output.public_key)),
            tx_out_hash: output.hash().into(),
            tombstone: 1,
            ..Default::default()
        };

        // A receipt with all key images in the same block is verified.
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![
                    (&KeyImage::from(1)).into(),
                    (&KeyImage::from(2)).into(),
                    (&KeyImage::from(3)).into(),
                ],
                tombstone: 1,
            };

            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone()],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.status(), api::TxStatus::Verified);
        }

        // A receipt with an extra key image should be
        // TransactionFailureKeyImageBlockMismatch.
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![
                    (&KeyImage::from(1)).into(),
                    (&KeyImage::from(2)).into(),
                    (&KeyImage::from(3)).into(),
                    (&KeyImage::from(4)).into(),
                ],
                tombstone: 1,
            };

            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone()],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.status(),
                api::TxStatus::TransactionFailureKeyImageBlockMismatch
            );
        }

        // A receipt with key images that are not in the ledger is pending (unknown) if
        // its tombstone block has not been exceeded.
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![(&KeyImage::from(4)).into(), (&KeyImage::from(5)).into()],
                tombstone: ledger_db.num_blocks().unwrap() + 1,
            };

            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone()],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.status(), api::TxStatus::Unknown);
        }

        // A receipt with key images that are not in the ledger having its tombstone
        // block exceeded.
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![(&KeyImage::from(4)).into(), (&KeyImage::from(5)).into()],
                tombstone: ledger_db.num_blocks().unwrap(),
            };

            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone()],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.status(), api::TxStatus::TombstoneBlockExceeded);
        }

        // Add another block to the ledger with different key images, to the same
        // recipient
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &[recipient.clone()],
            Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
            &[KeyImage::from(4), KeyImage::from(5), KeyImage::from(6)],
            &mut rng,
        )
        .unwrap();

        // A receipt with all the key_images in the ledger, but in different blocks,
        // should fail.
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![
                    (&KeyImage::from(1)).into(),
                    (&KeyImage::from(2)).into(),
                    (&KeyImage::from(4)).into(),
                ],
                tombstone: 1,
            };
            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone()],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.status(),
                api::TxStatus::TransactionFailureKeyImageBlockMismatch
            );
        }

        // Create receiver_tx_receipt based on the txout created in
        // add_block_to_ledger
        let block2 = ledger_db
            .get_block_contents(ledger_db.num_blocks().unwrap() - 1)
            .unwrap();
        let output2 = block2.outputs[0].clone();

        let receiver_receipt2 = api::ReceiverTxReceipt {
            recipient: Some(api::external::PublicAddress::from(&recipient)),
            tx_public_key: Some(api::external::CompressedRistretto::from(
                &output2.public_key,
            )),
            tx_out_hash: output2.hash().into(),
            tombstone: 1,
            ..Default::default()
        };

        // A receiver receipt with multiple public keys in different blocks should fail
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![(&KeyImage::from(1)).into(), (&KeyImage::from(2)).into()],
                tombstone: 1,
            };

            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt.clone(), receiver_receipt2],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.status(),
                api::TxStatus::PublicKeysInDifferentBlocks
            );
        }

        // A receipt with a public key which has not landed in the ledger, but
        // key_images which have should fail.
        // A receiver receipt with multiple public keys in different blocks should fail
        {
            let sender_receipt = api::SenderTxReceipt {
                key_image_list: vec![(&KeyImage::from(1)).into(), (&KeyImage::from(4)).into()],
                tombstone: 1,
            };
            // Modify the receiver_receipt to have a public key not in the ledger
            receiver_receipt.tx_public_key = Some(api::external::CompressedRistretto::from(
                &CompressedRistrettoPublic::from(&RistrettoPublic::from_random(&mut rng)),
            ));
            let request = api::SubmitTxResponse {
                sender_tx_receipt: Some(sender_receipt),
                receiver_tx_receipt_list: vec![receiver_receipt],
            };

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.status(),
                api::TxStatus::TransactionFailureKeyImageAlreadySpent
            );
        }
    }

    #[test_with_logger]
    fn test_get_tx_status_as_receiver_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // A call with an invalid hash should fail
        {
            let receipt = api::ReceiverTxReceipt {
                tombstone: 1,
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                ..Default::default()
            };

            assert!(client.get_tx_status_as_receiver(&request).is_err());
        }

        // A call with a hash thats in the ledger should return Verified
        {
            let tx_out = ledger_db.get_tx_out_by_index(1).unwrap();
            let hash = tx_out.hash();

            let receipt = api::ReceiverTxReceipt {
                tx_out_hash: hash.to_vec(),
                tombstone: 1,
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                ..Default::default()
            };

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.status(), api::TxStatus::Verified);
        }

        // A call with a hash thats is not in the ledger and hasn't exceeded tombstone
        // block should return Unknown
        {
            let hash = [0; 32];

            let receipt = api::ReceiverTxReceipt {
                tx_out_hash: hash.to_vec(),
                tombstone: ledger_db.num_blocks().unwrap() + 1,
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                ..Default::default()
            };

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.status(), api::TxStatus::Unknown);
        }

        // A call with a hash thats is not in the ledger and has exceeded tombstone
        // block should return TombstoneBlockExceeded
        {
            let hash = [0; 32];

            let receipt = api::ReceiverTxReceipt {
                tx_out_hash: hash.to_vec(),
                tombstone: ledger_db.num_blocks().unwrap(),
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                ..Default::default()
            };

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.status(), api::TxStatus::TombstoneBlockExceeded);
        }

        // Now create a monitor for the receiver to test confirmation numbers
        let receiver = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            receiver.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        let (tx_out, shared_secret) =
            create_tx_out(Amount::new(10, Mob::ID), &receiver.subaddress(0), &mut rng);
        let confirmation = TxOutConfirmationNumber::from(&shared_secret);

        add_txos_to_ledger(&mut ledger_db, BLOCK_VERSION, &[tx_out.clone()], &mut rng).unwrap();

        // A request with a valid confirmation number and monitor ID should return
        // Verified
        {
            let hash = tx_out.hash();

            let receipt = api::ReceiverTxReceipt {
                tx_public_key: Some(api::external::CompressedRistretto::from(&tx_out.public_key)),
                tx_out_hash: hash.to_vec(),
                tombstone: 10,
                confirmation_number: confirmation.to_vec(),
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                monitor_id: monitor_id.to_vec(),
            };

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.status(), api::TxStatus::Verified);
        }

        // A request with an a bad confirmation number and a monitor ID should return
        // InvalidConfirmationNumber
        {
            let hash = tx_out.hash();

            let receipt = api::ReceiverTxReceipt {
                tx_public_key: Some(api::external::CompressedRistretto::from(&tx_out.public_key)),
                tx_out_hash: hash.to_vec(),
                tombstone: 10,
                confirmation_number: vec![0u8; 32],
                ..Default::default()
            };

            let request = api::GetTxStatusAsReceiverRequest {
                receipt: Some(receipt),
                monitor_id: monitor_id.to_vec(),
            };

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.status(), api::TxStatus::InvalidConfirmationNumber);
        }
    }

    #[test_with_logger]
    fn test_get_processed_block(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        // Note: we skip the first block to test what happens when we try and query a
        // block that will never get processed.
        let monitor_data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            1,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[account_key.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify the data we got matches what we expected. This assumes knowledge about
        // how the test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().expect("failed getting num blocks");
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let block_contents = ledger_db.get_block_contents(idx).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                block_contents.outputs[3].clone()
            })
            .collect();

        let expected_utxos: Vec<UnspentTxOut> = account_tx_outs
            .iter()
            .map(|tx_out| {
                // Calculate the key image for this tx out.
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let onetime_private_key = recover_onetime_private_key(
                    &tx_public_key,
                    account_key.view_private_key(),
                    &account_key.subaddress_spend_private(0),
                );
                let key_image = KeyImage::from(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: 0,
                    key_image,
                    value: test_utils::DEFAULT_PER_RECIPIENT_AMOUNT,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                    token_id: *Mob::ID,
                    memo_payload: vec![],
                }
            })
            .collect();

        // Query a bunch of blocks and verify the data.
        for block_index in 1..num_blocks {
            let request = api::GetProcessedBlockRequest {
                monitor_id: monitor_id.to_vec(),
                block: block_index,
            };

            let response = client
                .get_processed_block(&request)
                .expect("failed to get processed block");

            // We expect one utxo per block for our monitor.
            let tx_outs = response.tx_outs;
            assert_eq!(tx_outs.len(), 1);
            let tx_out = &tx_outs[0];

            let expected_utxo = &expected_utxos[block_index as usize];

            assert_eq!(tx_out.monitor_id.to_vec(), monitor_id.to_vec());
            assert_eq!(tx_out.subaddress_index, expected_utxo.subaddress_index);
            assert_eq!(
                tx_out.public_key.as_ref().unwrap(),
                &(&expected_utxo.tx_out.public_key).into(),
            );
            assert_eq!(
                tx_out.key_image.as_ref().unwrap(),
                &(&expected_utxo.key_image).into()
            );
            assert_eq!(tx_out.value, expected_utxo.value);
            assert_eq!(tx_out.direction(), api::ProcessedTxOutDirection::Received,);

            // test address code
            let request = api::GetPublicAddressRequest {
                monitor_id: monitor_id.to_vec(),
                subaddress_index: expected_utxo.subaddress_index,
            };
            let response = client.get_public_address(&request).unwrap();
            let public_address =
                PublicAddress::try_from(response.public_address.as_ref().unwrap()).unwrap();

            let request = api::CreateAddressCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&public_address)),
            };
            let response = client.create_address_code(&request).unwrap();
            let b58_code = response.b58_code;

            assert_eq!(tx_out.address_code, b58_code);

            assert_eq!(tx_out.token_id, *Mob::ID);
        }

        // Add a block with a key images that spend the first two utxos and see that we
        // get the data we expect.
        {
            let recipient = AccountKey::random(&mut rng).default_subaddress();
            add_block_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                &[recipient],
                Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
                &[
                    expected_utxos[monitor_data.first_block as usize].key_image,
                    expected_utxos[monitor_data.first_block as usize + 1].key_image,
                ],
                &mut rng,
            )
            .unwrap();

            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            let request = api::GetProcessedBlockRequest {
                monitor_id: monitor_id.to_vec(),
                block: num_blocks,
            };

            let response = client
                .get_processed_block(&request)
                .expect("failed to get processed block");

            let tx_outs = response.tx_outs;
            assert_eq!(tx_outs.len(), 2);

            let expected_utxos_by_key_image = HashMap::from_iter(
                expected_utxos
                    .iter()
                    .skip(monitor_data.first_block as usize)
                    .take(2)
                    .map(|utxo| (utxo.key_image, utxo.clone())),
            );

            for tx_out in tx_outs.iter() {
                let expected_utxo = expected_utxos_by_key_image
                    .get(
                        &KeyImage::try_from(tx_out.key_image.as_ref().unwrap())
                            .expect("failed constructing key image"),
                    )
                    .expect("failed getting expected utxo");

                assert_eq!(tx_out.monitor_id.to_vec(), monitor_id.to_vec());
                assert_eq!(tx_out.subaddress_index, expected_utxo.subaddress_index);
                assert_eq!(
                    tx_out.public_key.as_ref().unwrap(),
                    &(&expected_utxo.tx_out.public_key).into(),
                );
                assert_eq!(
                    tx_out.key_image.as_ref().unwrap(),
                    &(&expected_utxo.key_image).into()
                );
                assert_eq!(tx_out.value, expected_utxo.value);
                assert_eq!(tx_out.direction(), api::ProcessedTxOutDirection::Spent,);
            }
        }

        // Add a block with a non-MOB token id and see that it gets picked up
        // correctly.
        {
            add_block_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                &[account_key.subaddress(5)],
                Amount::new(102030, 2.into()),
                &[KeyImage::from(101)],
                &mut rng,
            )
            .unwrap();

            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            let request = api::GetProcessedBlockRequest {
                monitor_id: monitor_id.to_vec(),
                block: num_blocks + 1,
            };

            let response = client
                .get_processed_block(&request)
                .expect("failed to get processed block");

            let tx_outs = response.tx_outs;
            assert_eq!(tx_outs.len(), 1);

            let tx_out = &tx_outs[0];
            assert_eq!(tx_out.monitor_id.to_vec(), monitor_id.to_vec());
            assert_eq!(tx_out.value, 102030);
            assert_eq!(tx_out.direction(), api::ProcessedTxOutDirection::Received);
            assert_eq!(tx_out.token_id, 2);
        }

        // Query a block that will never get processed since its before the monitor's
        // first block.
        let request = api::GetProcessedBlockRequest {
            monitor_id: monitor_id.to_vec(),
            block: 0,
        };

        assert!(client.get_processed_block(&request).is_err());

        // Query a block that hasn't been processed yet.
        let request = api::GetProcessedBlockRequest {
            monitor_id: monitor_id.to_vec(),
            block: num_blocks + 2,
        };

        assert!(client.get_processed_block(&request).is_err());

        // Query with an unknown monitor id.
        let request = api::GetProcessedBlockRequest {
            monitor_id: vec![1; 32],
            block: 1,
        };

        assert!(client.get_processed_block(&request).is_err());
    }

    #[test_with_logger]
    /// Get mixins should return the correct number of distinct mixins.
    fn test_get_mixins(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([44u8; 32]);

        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger,
                &mut rng,
            );

        // The ledger contains 40 transaction outputs.
        assert_eq!(ledger_db.num_txos().unwrap(), 40);

        // Response should contain the requested number of distinct mixins.
        {
            let request = api::GetMixinsRequest {
                num_mixins: 13,
                ..Default::default()
            };
            let response = client.get_mixins(&request).unwrap();
            let mixins_with_proofs: Vec<api::TxOutWithProof> = response.mixins.to_vec();

            assert_eq!(mixins_with_proofs.len(), 13);

            // Mixins should be distinct.
            let mixin_hashes: HashSet<_> = mixins_with_proofs
                .iter()
                .map(|mixin| {
                    let tx_out: TxOut = TxOut::try_from(mixin.output.as_ref().unwrap()).unwrap();
                    tx_out.hash()
                })
                .collect();

            assert_eq!(mixin_hashes.len(), mixins_with_proofs.len());
        }

        // Requesting more mixins than exist in the ledger should return an error.
        // TODO: enforce a limit on the number of mixins that may be requested.
        {
            let bad_request = api::GetMixinsRequest {
                num_mixins: 10000,
                ..Default::default()
            };
            let response = client.get_mixins(&bad_request);

            assert!(response.is_err());
        }
    }

    #[test_with_logger]
    /// Get mixins should not return an "excluded" TxOut.
    fn test_get_mixins_excluded(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([74u8; 32]);

        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        assert_eq!(ledger_db.num_txos().unwrap(), 40);

        // A list of outputs to exclude.
        let to_exclude: Vec<TxOut> = {
            let data = MonitorData::new(
                sender, 0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .unwrap();

            // Insert into database.
            let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

            // Allow the new monitor to process the ledger.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Select some outputs from the ledger.
            mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap()
                .into_iter()
                .map(|utxo| utxo.tx_out)
                .collect()
        };

        assert_eq!(to_exclude.len(), 10);

        // The ledger contains 40 outputs. Requesting 30 and excluding 10 should return
        // exactly the remaining 30.
        let request = api::GetMixinsRequest {
            num_mixins: 30,
            excluded: to_exclude.iter().map(api::external::TxOut::from).collect(),
        };

        let response = client.get_mixins(&request).unwrap();

        let mixins_with_proofs: Vec<api::TxOutWithProof> = response.mixins.to_vec();

        // Should contain 30 mixins
        assert_eq!(mixins_with_proofs.len(), 30);

        // None of the excluded outputs should be returned as mixins.
        let excluded_hashes: HashSet<_> = to_exclude.iter().map(|tx_out| tx_out.hash()).collect();

        for mixin in &mixins_with_proofs {
            let mixin: TxOut = TxOut::try_from(mixin.output.as_ref().unwrap()).unwrap();
            assert!(!excluded_hashes.contains(&mixin.hash()));
        }
    }

    #[test_with_logger]
    /// Get mixins should return valid membership proofs.
    fn test_get_mixins_membership_proofs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([89u8; 32]);
        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger,
                &mut rng,
            );

        let mixins_with_proofs: Vec<api::TxOutWithProof> = {
            let request = api::GetMixinsRequest {
                num_mixins: 13,
                ..Default::default()
            };
            let response = client.get_mixins(&request).unwrap();
            response.mixins.to_vec()
        };

        assert_eq!(mixins_with_proofs.len(), 13);

        // Each membership proof should be correct.
        for mixin_with_proof in &mixins_with_proofs {
            let mixin: TxOut = TxOut::try_from(mixin_with_proof.output.as_ref().unwrap()).unwrap();

            // The returned proof should be correct.
            let expected_proof = {
                let index = ledger_db.get_tx_out_index_by_hash(&mixin.hash()).unwrap();
                let proofs = ledger_db.get_tx_out_proof_of_memberships(&[index]).unwrap();
                assert_eq!(proofs.len(), 1);
                api::external::TxOutMembershipProof::from(&proofs[0])
            };

            assert_eq!(mixin_with_proof.proof.as_ref().unwrap(), &expected_proof);
        }
    }

    #[test_with_logger]
    /// Should return a correct proof-of-membership for each requested TxOut.
    fn test_get_membership_proofs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Select some outputs from the ledger.
        let outputs: Vec<TxOut> = {
            let unspent_outputs = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();

            vec![
                unspent_outputs[1].tx_out.clone(),
                unspent_outputs[3].tx_out.clone(),
                unspent_outputs[5].tx_out.clone(),
            ]
        };

        // Try with only outputs
        let request = api::GetMembershipProofsRequest {
            outputs: outputs.iter().map(api::external::TxOut::from).collect(),
            ..Default::default()
        };

        let response = client.get_membership_proofs(&request).unwrap();

        // The response should should contain an element for each requested output.
        assert_eq!(response.output_list.len(), outputs.len());

        for (tx_out, output_with_proof) in outputs.iter().zip(response.output_list.iter()) {
            // The response should contain a TxOutWithProof for each requested TxOut.
            assert_eq!(
                output_with_proof.output.as_ref().unwrap(),
                &api::external::TxOut::from(tx_out)
            );

            // The returned proof should be correct.
            let expected_proof = {
                let index = ledger_db.get_tx_out_index_by_hash(&tx_out.hash()).unwrap();
                let proofs = ledger_db.get_tx_out_proof_of_memberships(&[index]).unwrap();
                assert_eq!(proofs.len(), 1);

                api::external::TxOutMembershipProof::from(&proofs[0])
            };

            assert_eq!(output_with_proof.proof.as_ref().unwrap(), &expected_proof);
        }

        // Try with only indices, we should receive an identical response.
        let request2 = api::GetMembershipProofsRequest {
            indices: vec![
                ledger_db
                    .get_tx_out_index_by_hash(&outputs[0].hash())
                    .unwrap(),
                ledger_db
                    .get_tx_out_index_by_hash(&outputs[1].hash())
                    .unwrap(),
                ledger_db
                    .get_tx_out_index_by_hash(&outputs[2].hash())
                    .unwrap(),
            ],
            ..Default::default()
        };

        let response2 = client.get_membership_proofs(&request2).unwrap();

        assert_eq!(response, response2);

        // Try with no indices or outputs
        let request3 = api::GetMembershipProofsRequest::default();
        let response3 = client.get_membership_proofs(&request3).unwrap();
        assert!(response3.output_list.is_empty());

        // Try with both, we should get an error.
        let request4 = api::GetMembershipProofsRequest {
            outputs: outputs.iter().map(api::external::TxOut::from).collect(),
            indices: vec![1],
        };
        assert!(client.get_membership_proofs(&request4).is_err());
    }

    #[test_with_logger]
    fn test_generate_swap(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                sender.default_subaddress(),
            ],
            Amount::new(1_000_000_000_000, TokenId::from(1)),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Call generate swap.
        let request = api::GenerateSwapRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input: Some(
                utxos
                    .iter()
                    .filter(|utxo| utxo.token_id == *Mob::ID)
                    .map(api::UnspentTxOut::from)
                    .next()
                    .unwrap(),
            ),
            allow_partial_fill: true,
            counter_value: 123,
            counter_token_id: 1,
            minimum_fill_value: 10,
            ..Default::default()
        };

        // Test the happy flow for MOB -> eUSD, partial fill swap
        {
            let response = client.generate_swap(&request).unwrap();

            // Sanity test the response.
            let sci = response.sci.as_ref().unwrap();

            assert_eq!(sci.tx_out_global_indices.len(), 11);
            assert_eq!(sci.required_output_amounts.len(), 0);

            let tx_in = sci.tx_in.as_ref().unwrap();
            assert_eq!(tx_in.ring.len(), 11);

            let rules = tx_in.input_rules.as_ref().unwrap();
            assert_eq!(rules.required_outputs.len(), 0);
            assert_eq!(rules.partial_fill_outputs.len(), 1);
            assert!(rules.partial_fill_change.as_ref().is_some());
            assert_eq!(rules.max_tombstone_block, 0);
            assert_eq!(rules.min_partial_fill_value, 10);

            let sci = SignedContingentInput::try_from(sci).unwrap();

            sci.validate().unwrap();

            let (amount, _scalar) = sci.tx_in.input_rules.as_ref().unwrap().partial_fill_outputs[0]
                .reveal_amount()
                .unwrap();
            assert_eq!(amount.value, 123);
            assert_eq!(amount.token_id, TokenId::from(1));

            // Validate ring vs. indices, as deqs does
            let indices = &sci.tx_out_global_indices;
            let ring = &sci.tx_in.ring;
            for (index, tx_out) in indices.iter().zip(ring.iter()) {
                let real_tx_out = ledger_db.get_tx_out_by_index(*index).unwrap();
                assert_eq!(&real_tx_out, tx_out, "Mismatch at index {index}");
            }
        }

        // Test the happy flow for eUSD -> MOB, non partial fill swap
        {
            let request = api::GenerateSwapRequest {
                sender_monitor_id: monitor_id.to_vec(),
                change_subaddress: 0,
                input: Some(
                    utxos
                        .iter()
                        .filter(|utxo| utxo.token_id == 1)
                        .map(api::UnspentTxOut::from)
                        .next()
                        .unwrap(),
                ),
                allow_partial_fill: false,
                counter_value: 999_999,
                counter_token_id: 0,
                minimum_fill_value: 10,
                tombstone: 1000,
            };

            let response = client.generate_swap(&request).unwrap();

            // Sanity test the response.
            let sci = response.sci.as_ref().unwrap();
            assert_eq!(sci.tx_out_global_indices.len(), 11);
            assert_eq!(sci.required_output_amounts.len(), 1);

            let tx_in = sci.tx_in.as_ref().unwrap();
            assert_eq!(tx_in.ring.len(), 11);

            let rules = tx_in.input_rules.as_ref().unwrap();
            assert_eq!(rules.required_outputs.len(), 1);
            assert_eq!(rules.partial_fill_outputs.len(), 0);
            assert!(rules.partial_fill_change.as_ref().is_none());
            assert_eq!(rules.max_tombstone_block, 1000);
            assert_eq!(rules.min_partial_fill_value, 0);

            let sci = SignedContingentInput::try_from(sci).unwrap();

            sci.validate().unwrap();
            assert_eq!(sci.tx_out_global_indices.len(), 11);
            // Indices should be distinct
            assert_eq!(
                HashSet::from_iter(sci.tx_out_global_indices.iter()).len(),
                11
            );

            let unmasked_amount = sci.required_output_amounts[0].clone();
            assert_eq!(unmasked_amount.value, 999_999);
            assert_eq!(unmasked_amount.token_id, *Mob::ID);

            // Validate ring vs. indices, as deqs does
            let indices = &sci.tx_out_global_indices;
            let ring = &sci.tx_in.ring;
            for (index, tx_out) in indices.iter().zip(ring.iter()) {
                let real_tx_out = ledger_db.get_tx_out_by_index(*index).unwrap();
                assert_eq!(&real_tx_out, tx_out, "Mismatch at index {index}");
            }
        }

        // Invalid input scenarios should result in an error.
        {
            // No monitor id
            let mut request = request.clone();
            request.sender_monitor_id = vec![];
            assert!(client.generate_swap(&request).is_err());
        }

        {
            // Unrecognized monitor id
            let sender = AccountKey::random(&mut rng);
            let data = MonitorData::new(
                sender, 0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .unwrap();

            let mut request = request.clone();
            request.sender_monitor_id = MonitorId::from(&data).to_vec();
            assert!(client.generate_swap(&request).is_err());
        }

        {
            // Subaddress index out of range
            let mut request = request.clone();
            request.change_subaddress = data.first_subaddress + data.num_subaddresses + 1;
            assert!(client.generate_swap(&request).is_err());
        }

        {
            // Junk input
            let mut request = request.clone();
            request.input = Some(api::UnspentTxOut::default());
            assert!(client.generate_swap(&request).is_err());
        }

        {
            // Counter value of zero is an error
            let mut request = request.clone();
            request.counter_value = 0;
            assert!(client.generate_swap(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_generate_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                sender.default_subaddress(),
            ],
            Amount::new(1_000_000_000_000, TokenId::from(2)),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call generate tx.
        let request = api::GenerateTxRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos
                .iter()
                .filter(|utxo| utxo.token_id == *Mob::ID)
                .map(api::UnspentTxOut::from)
                .collect(),
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        // Test the happy flow for MOB.
        {
            let response = client.generate_tx(&request).unwrap();

            // Sanity test the response.
            let tx_proposal = response.tx_proposal.as_ref().unwrap();

            let expected_num_inputs: u64 = (outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                / test_utils::DEFAULT_PER_RECIPIENT_AMOUNT)
                + 1;
            assert_eq!(tx_proposal.input_list.len(), expected_num_inputs as usize);
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .inputs
                    .len(),
                expected_num_inputs as usize
            );
            assert_eq!(
                tx_proposal.outlay_list,
                request
                    .outlay_list
                    .iter()
                    .map(|outlay| api::OutlayV2::new_from_outlay_and_token_id(outlay, *Mob::ID))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .outputs
                    .len(),
                outlays.len() + 1
            ); // Extra output for change.

            let tx = Tx::try_from(tx_proposal.tx.as_ref().unwrap()).unwrap();

            // The transaction should contain an output for each outlay, and one for change.
            assert_eq!(tx.prefix.outputs.len(), outlays.len() + 1);

            // The transaction should have a confirmation code for each outlay
            assert_eq!(outlays.len(), tx_proposal.outlay_confirmation_numbers.len());

            let change_value = test_utils::DEFAULT_PER_RECIPIENT_AMOUNT
                - outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                - Mob::MINIMUM_FEE;

            for (account_key, expected_value) in &[
                (&receiver1, outlays[0].value),
                (&receiver2, outlays[1].value),
                (&sender, change_value),
            ] {
                // Find the first output belonging to the account, and get its value.
                // This assumes that each output is sent to a different account key.
                let ((amount, _blinding), tx_out, shared_secret) = tx
                    .prefix
                    .outputs
                    .iter()
                    .find_map(|tx_out| {
                        let output_public_key =
                            RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                        let shared_secret = get_tx_out_shared_secret(
                            account_key.view_private_key(),
                            &output_public_key,
                        );
                        tx_out
                            .get_masked_amount()
                            .unwrap()
                            .get_value(&shared_secret)
                            .ok()
                            .map(|amount| (amount, tx_out, shared_secret))
                    })
                    .expect("There should be an output belonging to the account key.");

                assert_eq!(amount.token_id, Mob::ID);
                assert_eq!(amount.value, *expected_value);

                // Receivers get an AuthenticatedSender memo, sender gets a DestinationMemo
                let memo = tx_out.e_memo.as_ref().unwrap().decrypt(&shared_secret);
                if account_key == &&sender {
                    assert_matches!(
                        MemoType::try_from(&memo).unwrap(),
                        MemoType::Destination(dst_memo)
                        if dst_memo.get_num_recipients() == 2 &&
                            dst_memo.get_total_outlay() == outlays.iter().map(|outlay| outlay.value).sum::<u64>() + dst_memo.get_fee()
                    );
                } else {
                    assert_matches!(
                        MemoType::try_from(&memo).unwrap(),
                        MemoType::AuthenticatedSender(authenticated_sender_memo)
                        if authenticated_sender_memo.validate(&sender.default_subaddress(), &account_key.default_subaddress_view_private(), &tx_out.public_key).unwrap_u8() == 1
                    );
                }
            }

            // Santity test fee
            assert_eq!(tx_proposal.fee, Mob::MINIMUM_FEE);
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .fee,
                Mob::MINIMUM_FEE
            );

            // Sanity test tombstone block
            let num_blocks = ledger_db.num_blocks().unwrap();
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .tombstone_block,
                num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
            );
        }

        // Test the happy flow for TokenId(2)
        {
            let fee = 10_000;
            let request = api::GenerateTxRequest {
                sender_monitor_id: monitor_id.to_vec(),
                change_subaddress: 0,
                input_list: utxos
                    .iter()
                    .filter(|utxo| utxo.token_id == 2)
                    .map(api::UnspentTxOut::from)
                    .collect(),
                outlay_list: outlays.iter().map(api::Outlay::from).collect(),
                token_id: 2,
                fee,
                ..Default::default()
            };

            let response = client.generate_tx(&request).unwrap();

            // Sanity test the response.
            let tx_proposal = response.tx_proposal.as_ref().unwrap();

            assert_eq!(tx_proposal.input_list.len(), 1,);
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .inputs
                    .len(),
                1,
            );
            assert_eq!(
                tx_proposal.outlay_list,
                request
                    .outlay_list
                    .iter()
                    .map(|outlay| api::OutlayV2::new_from_outlay_and_token_id(outlay, 2))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .outputs
                    .len(),
                outlays.len() + 1
            ); // Extra output for change.

            let tx = Tx::try_from(tx_proposal.tx.as_ref().unwrap()).unwrap();

            // The transaction should contain an output for each outlay, and one for change.
            assert_eq!(tx.prefix.outputs.len(), outlays.len() + 1);

            // The transaction should have a confirmation code for each outlay
            assert_eq!(outlays.len(), tx_proposal.outlay_confirmation_numbers.len());

            let change_value =
                1_000_000_000_000 - outlays.iter().map(|outlay| outlay.value).sum::<u64>() - fee;

            for (account_key, expected_value) in &[
                (&receiver1, outlays[0].value),
                (&receiver2, outlays[1].value),
                (&sender, change_value),
            ] {
                // Find the first output belonging to the account, and get its value.
                // This assumes that each output is sent to a different account key.
                let ((amount, _blinding), tx_out, shared_secret) = tx
                    .prefix
                    .outputs
                    .iter()
                    .find_map(|tx_out| {
                        let output_public_key =
                            RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                        let shared_secret = get_tx_out_shared_secret(
                            account_key.view_private_key(),
                            &output_public_key,
                        );
                        tx_out
                            .get_masked_amount()
                            .unwrap()
                            .get_value(&shared_secret)
                            .ok()
                            .map(|amount| (amount, tx_out, shared_secret))
                    })
                    .expect("There should be an output belonging to the account key.");

                assert_eq!(amount.token_id, TokenId::from(2));
                assert_eq!(amount.value, *expected_value);

                // Receivers get an AuthenticatedSender memo, sender gets a DestinationMemo
                let memo = tx_out.e_memo.as_ref().unwrap().decrypt(&shared_secret);
                if account_key == &&sender {
                    assert_matches!(
                        MemoType::try_from(&memo).unwrap(),
                        MemoType::Destination(dst_memo)
                        if dst_memo.get_num_recipients() == 2 &&
                            dst_memo.get_total_outlay() == outlays.iter().map(|outlay| outlay.value).sum::<u64>() + dst_memo.get_fee()
                    );
                } else {
                    assert_matches!(
                        MemoType::try_from(&memo).unwrap(),
                        MemoType::AuthenticatedSender(authenticated_sender_memo)
                        if authenticated_sender_memo.validate(&sender.default_subaddress(), &account_key.default_subaddress_view_private(), &tx_out.public_key).unwrap_u8() == 1
                    );
                }
            }

            // Santity test fee
            assert_eq!(tx_proposal.fee, fee);
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .fee,
                fee
            );

            // Sanity test tombstone block
            let num_blocks = ledger_db.num_blocks().unwrap();
            assert_eq!(
                tx_proposal
                    .tx
                    .as_ref()
                    .unwrap()
                    .prefix
                    .as_ref()
                    .unwrap()
                    .tombstone_block,
                num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
            );
        }

        // Invalid input scenarios should result in an error.
        {
            // No monitor id
            let mut request = request.clone();
            request.sender_monitor_id = vec![];
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Unrecognized monitor id
            let sender = AccountKey::random(&mut rng);
            let data = MonitorData::new(
                sender, 0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
                "", // name
            )
            .unwrap();

            let mut request = request.clone();
            request.sender_monitor_id = MonitorId::from(&data).to_vec();
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Subaddress index out of range
            let mut request = request.clone();
            request.change_subaddress = data.first_subaddress + data.num_subaddresses + 1;
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Junk input
            let mut request = request.clone();
            request.input_list.push(api::UnspentTxOut::default());
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Attempt to spend more than we have
            let num_blocks = ledger_db.num_blocks().unwrap();
            let mut request = request.clone();
            request.outlay_list = vec![api::Outlay::from(&Outlay {
                receiver: receiver1.default_subaddress(),
                value: test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * num_blocks,
                tx_private_key: None,
            })];
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Mixing input tokens (utxos has both Mob and TokenId(2))
            let request = api::GenerateTxRequest {
                sender_monitor_id: monitor_id.to_vec(),
                change_subaddress: 0,
                input_list: utxos.iter().map(api::UnspentTxOut::from).collect(),
                outlay_list: outlays.iter().map(api::Outlay::from).collect(),
                ..Default::default()
            };
            assert!(client.generate_tx(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_generate_tx_explicit_memo(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                sender.default_subaddress(),
            ],
            Amount::new(1_000_000_000_000, TokenId::from(2)),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate random recipient.
        let receiver1 = AccountKey::random(&mut rng);

        let outlays = vec![Outlay {
            value: 123,
            receiver: receiver1.default_subaddress(),
            tx_private_key: None,
        }];

        // Call generate tx.
        let rth = mc_mobilecoind_api::TransactionMemoRth {
            payment_id: Some(transaction_memo_rth::PaymentId::PaymentRequestId(55551)),
            ..Default::default()
        };
        let request = api::GenerateTxRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos
                .iter()
                .filter(|utxo| utxo.token_id == *Mob::ID)
                .map(api::UnspentTxOut::from)
                .collect(),
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            memo: Some(mc_mobilecoind_api::TransactionMemo {
                transaction_memo: Some(mc_mobilecoind_api::transaction_memo::TransactionMemo::Rth(
                    rth,
                )),
            }),
            ..Default::default()
        };

        let response = client.generate_tx(&request).unwrap();
        let default_tx_proposal = Default::default();
        let tx_proposal = response
            .tx_proposal
            .as_ref()
            .unwrap_or(&default_tx_proposal);
        let tx = Tx::try_from(tx_proposal.tx.as_ref().unwrap()).unwrap();

        // The transaction should contain two outputs (outlay + change)
        assert_eq!(tx.prefix.outputs.len(), 2);

        let change_value = test_utils::DEFAULT_PER_RECIPIENT_AMOUNT
            - outlays.iter().map(|outlay| outlay.value).sum::<u64>()
            - Mob::MINIMUM_FEE;

        for (account_key, expected_value) in
            &[(&receiver1, outlays[0].value), (&sender, change_value)]
        {
            // Find the first output belonging to the account, and get its value.
            // This assumes that each output is sent to a different account key.
            let ((amount, _blinding), tx_out, shared_secret) = tx
                .prefix
                .outputs
                .iter()
                .find_map(|tx_out| {
                    let output_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                    let shared_secret = get_tx_out_shared_secret(
                        account_key.view_private_key(),
                        &output_public_key,
                    );
                    tx_out
                        .get_masked_amount()
                        .unwrap()
                        .get_value(&shared_secret)
                        .ok()
                        .map(|amount| (amount, tx_out, shared_secret))
                })
                .expect("There should be an output belonging to the account key.");

            assert_eq!(amount.token_id, Mob::ID);
            assert_eq!(amount.value, *expected_value);

            // Receivers get an AuthenticatedSender memo, sender gets a DestinationMemo
            let memo = tx_out.e_memo.as_ref().unwrap().decrypt(&shared_secret);
            if account_key == &&sender {
                assert_matches!(
                    MemoType::try_from(&memo).unwrap(),
                    MemoType::DestinationWithPaymentRequestId(dst_memo)
                    if dst_memo.get_num_recipients() == 1 &&
                        dst_memo.get_total_outlay() == outlays.iter().map(|outlay| outlay.value).sum::<u64>() + dst_memo.get_fee() &&
                        dst_memo.get_payment_request_id() == 55551
                );
            } else {
                assert_matches!(
                    MemoType::try_from(&memo).unwrap(),
                    MemoType::AuthenticatedSenderWithPaymentRequestId(authenticated_sender_memo)
                    if authenticated_sender_memo.validate(&sender.default_subaddress(), &account_key.default_subaddress_view_private(), &tx_out.public_key).unwrap_u8() == 1 &&
                        authenticated_sender_memo.payment_request_id() == 55551
                );
            }
        }
    }

    #[test_with_logger]
    fn test_generate_mixed_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let swap_originator = AccountKey::random(&mut rng);
        let swap_originator_data = MonitorData::new(
            swap_originator.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        let swap_counterparty = AccountKey::random(&mut rng);
        let swap_counterparty_data = MonitorData::new(
            swap_counterparty.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[
                    swap_originator.default_subaddress(),
                    swap_counterparty.default_subaddress(),
                ],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                swap_originator.default_subaddress(),
                swap_counterparty.default_subaddress(),
            ],
            Amount::new(1_000_000_000_000, TokenId::from(1)),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let originator_monitor_id = mobilecoind_db.add_monitor(&swap_originator_data).unwrap();
        let counterparty_monitor_id = mobilecoind_db.add_monitor(&swap_counterparty_data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&originator_monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        let offered_input = utxos
            .iter()
            .filter(|utxo| utxo.token_id == *Mob::ID)
            .map(api::UnspentTxOut::from)
            .next()
            .unwrap();
        let offered_value = offered_input.value;

        // Generate a swap.
        let generate_swap_response = {
            let request = api::GenerateSwapRequest {
                sender_monitor_id: originator_monitor_id.to_vec(),
                change_subaddress: 0,
                input: Some(offered_input),
                allow_partial_fill: true,
                counter_value: 123,
                counter_token_id: 1,
                minimum_fill_value: 10,
                ..Default::default()
            };
            client.generate_swap(&request).unwrap()
        };
        let generated_sci =
            SignedContingentInput::try_from(generate_swap_response.sci.as_ref().unwrap()).unwrap();
        generated_sci.validate().unwrap();

        // Now we will try to build a transaction that incorporates the swap.
        // The counterparty needs to supply eUSD.
        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&counterparty_monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());
        let counterparty_eusd_utxo_value =
            utxos.iter().find(|utxo| utxo.token_id == 1).unwrap().value;
        // Confirm my testing assumptions -- all eusd utxos here have the same value
        assert!(utxos
            .iter()
            .filter(|utxo| utxo.token_id == 1)
            .all(|utxo| utxo.value == counterparty_eusd_utxo_value));

        // We will try to take one quarter of the offered input.
        let sci_for_tx = api::SciForTx {
            sci: Some(generate_swap_response.sci.as_ref().unwrap().clone()),
            partial_fill_value: offered_value / 4,
        };

        // Try to add the swap to a mixed transaction
        let mut request = api::GenerateMixedTxRequest {
            sender_monitor_id: counterparty_monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos
                .iter()
                .filter(|utxo| utxo.token_id == 1)
                .map(Into::into)
                .collect(),
            scis: vec![sci_for_tx],
            ..Default::default()
        };
        let generate_mixed_tx_response = client.generate_mixed_tx(&request).unwrap();

        assert_eq!(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .scis
                .len(),
            1
        );
        let response_sci = SignedContingentInput::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .scis[0]
                .sci
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response_sci, generated_sci);

        let tx = Tx::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .tx
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(tx.prefix.outputs.len(), 4);

        let mut found_counterparty_output = false;
        let mut found_counterparty_change = false;
        let mut found_originator_output = false;
        let mut found_originator_change = false;
        for output in tx.prefix.outputs.iter() {
            if let Ok((amount, _scalar)) =
                output.view_key_match(swap_counterparty.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value / 4 - Mob::MINIMUM_FEE);
                    assert_eq!(tx.prefix.fee, Mob::MINIMUM_FEE);
                    assert_eq!(tx.prefix.fee_token_id, *Mob::ID);
                    found_counterparty_output = true;
                } else {
                    assert_eq!(*amount.token_id, 1);
                    // The quote asks for 123 eusd, counterparty fulfills to 1/4,
                    // rounding up so they give away 31.
                    // Change is their eusd utxo value minus that.
                    assert_eq!(amount.value, counterparty_eusd_utxo_value - 31);
                    found_counterparty_change = true;
                }
            } else if let Ok((amount, _scalar)) =
                output.view_key_match(swap_originator.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value * 3 / 4);
                    found_originator_change = true;
                } else {
                    // 31 is 1/4 of 123, rounded up
                    assert_eq!(amount, Amount::new(31, TokenId::from(1)));
                    found_originator_output = true;
                }
            }
        }
        assert!(found_counterparty_output);
        assert!(found_counterparty_change);
        assert!(found_originator_output);
        assert!(found_originator_change);

        // Changing the fee token id to 1 should work, and slightly adjust the output
        // values.
        request.fee_token_id = 1;

        let generate_mixed_tx_response = client.generate_mixed_tx(&request).unwrap();
        let response_sci = SignedContingentInput::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .scis[0]
                .sci
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response_sci, generated_sci);

        let tx = Tx::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .tx
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(tx.prefix.outputs.len(), 4);

        let mut found_counterparty_output = false;
        let mut found_counterparty_change = false;
        let mut found_originator_output = false;
        let mut found_originator_change = false;
        for output in tx.prefix.outputs.iter() {
            if let Ok((amount, _scalar)) =
                output.view_key_match(swap_counterparty.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value / 4);
                    found_counterparty_output = true;
                } else {
                    assert_eq!(*amount.token_id, 1);
                    // The quote asks for 123 eusd, counterparty fulfills to 1/4,
                    // rounding up so they give away 31.
                    // Change is their eusd utxo value minus that, minus the eusd transaction fee.
                    let default_fee_val = get_test_fee_map()
                        .get_fee_for_token(&TokenId::from(1))
                        .unwrap();
                    assert_eq!(
                        amount.value,
                        counterparty_eusd_utxo_value - 31 - default_fee_val
                    );
                    assert_eq!(tx.prefix.fee, default_fee_val);
                    assert_eq!(tx.prefix.fee_token_id, 1);
                    found_counterparty_change = true;
                }
            } else if let Ok((amount, _scalar)) =
                output.view_key_match(swap_originator.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value * 3 / 4);
                    found_originator_change = true;
                } else {
                    // 31 is 1/4 of 123, rounded up
                    assert_eq!(amount, Amount::new(31, TokenId::from(1)));
                    found_originator_output = true;
                }
            }
        }
        assert!(found_counterparty_output);
        assert!(found_counterparty_change);
        assert!(found_originator_output);
        assert!(found_originator_change);

        // Changing the fee in the request should work, and slightly adjust the output
        // values.
        let fee_override = 500_000;
        request.fee = fee_override;

        let generate_mixed_tx_response = client.generate_mixed_tx(&request).unwrap();
        let response_sci = SignedContingentInput::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .scis[0]
                .sci
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(response_sci, generated_sci);

        let tx = Tx::try_from(
            generate_mixed_tx_response
                .tx_proposal
                .as_ref()
                .unwrap()
                .tx
                .as_ref()
                .unwrap(),
        )
        .unwrap();

        assert_eq!(tx.prefix.outputs.len(), 4);

        let mut found_counterparty_output = false;
        let mut found_counterparty_change = false;
        let mut found_originator_output = false;
        let mut found_originator_change = false;
        for output in tx.prefix.outputs.iter() {
            if let Ok((amount, _scalar)) =
                output.view_key_match(swap_counterparty.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value / 4);
                    found_counterparty_output = true;
                } else {
                    assert_eq!(*amount.token_id, 1);
                    // The quote asks for 123 eusd, counterparty fulfills to 1/4,
                    // rounding up so they give away 31.
                    // Change is their eusd utxo value minus that, minus the eusd transaction fee.
                    assert_eq!(
                        amount.value,
                        counterparty_eusd_utxo_value - 31 - fee_override
                    );
                    assert_eq!(tx.prefix.fee, fee_override);
                    assert_eq!(tx.prefix.fee_token_id, 1);
                    found_counterparty_change = true;
                }
            } else if let Ok((amount, _scalar)) =
                output.view_key_match(swap_originator.view_private_key())
            {
                if amount.token_id == Mob::ID {
                    assert_eq!(amount.value, offered_value * 3 / 4);
                    found_originator_change = true;
                } else {
                    // 31 is 1/4 of 123, rounded up
                    assert_eq!(amount, Amount::new(31, TokenId::from(1)));
                    found_originator_output = true;
                }
            }
        }
        assert!(found_counterparty_output);
        assert!(found_counterparty_change);
        assert!(found_originator_output);
        assert!(found_originator_change);

        // Omitting the input list should result in an error
        request.input_list = vec![];
        assert!(client.generate_mixed_tx(&request).is_err());

        // Omitting the inputs with token id 1, which is needed, should give an error
        request.input_list = utxos
            .iter()
            .filter(|utxo| utxo.token_id == 0)
            .map(Into::into)
            .collect();
        assert!(client.generate_mixed_tx(&request).is_err());
    }

    #[test_with_logger]
    fn test_generate_burn_redemption_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);
        let token_id2 = TokenId::from(2);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a block with a non-MOB token ID.
        add_block_to_ledger(
            &mut ledger_db,
            BlockVersion::MAX,
            &[
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                AccountKey::random(&mut rng).default_subaddress(),
                sender.default_subaddress(),
            ],
            Amount::new(1_000_000_000_000, token_id2),
            &[KeyImage::from(101)],
            &mut rng,
        )
        .unwrap();

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs that we want to burn
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap()
            .iter()
            .filter(|utxo| utxo.token_id == token_id2)
            .map(Into::into)
            .collect::<Vec<_>>();
        assert!(!utxos.is_empty());

        // Prepare request
        let request = api::GenerateBurnRedemptionTxRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos,
            burn_amount: 100_000,
            fee: 200_000,
            token_id: *token_id2,
            redemption_memo: vec![5u8; BurnRedemptionMemo::MEMO_DATA_LEN],
            enable_destination_memo: true,
            ..Default::default()
        };

        // Test the happy flow.
        {
            let response = client.generate_burn_redemption_tx(&request).unwrap();

            // Sanity test the response.
            let tx_proposal = response.tx_proposal.as_ref().unwrap();
            let tx = Tx::try_from(tx_proposal.tx.as_ref().unwrap()).unwrap();

            // Two outputs - change and burn
            assert_eq!(tx.prefix.outputs.len(), 2);

            // Validate the change output.
            let (change_tx_out, change_amount) = tx
                .prefix
                .outputs
                .iter()
                .find_map(|tx_out| {
                    tx_out
                        .view_key_match(sender.view_private_key())
                        .map(|(amount, _commitment)| (tx_out.clone(), amount))
                        .ok()
                })
                .expect("Didn't find sender's change output");

            assert_eq!(change_amount.value, 1_000_000_000_000 - 100_000 - 200_000);

            let ss = get_tx_out_shared_secret(
                sender.view_private_key(),
                &RistrettoPublic::try_from(&change_tx_out.public_key).unwrap(),
            );
            let memo = change_tx_out.e_memo.unwrap().decrypt(&ss);
            match MemoType::try_from(&memo).expect("Couldn't decrypt memo") {
                MemoType::Destination(memo) => {
                    assert_eq!(
                        memo.get_address_hash(),
                        &ShortAddressHash::from(&burn_address()),
                        "lookup based on address hash failed"
                    );
                    assert_eq!(memo.get_num_recipients(), 1);
                    assert_eq!(memo.get_fee(), 200_000);
                    assert_eq!(
                        memo.get_total_outlay(),
                        300_000,
                        "outlay should be amount sent to recipient + fee"
                    );
                }
                _ => {
                    panic!("unexpected memo type")
                }
            }

            // Validate the burn output.
            let (burn_tx_out, burn_amount) = tx
                .prefix
                .outputs
                .iter()
                .find_map(|tx_out| {
                    tx_out
                        .view_key_match(&burn_address_view_private())
                        .map(|(amount, _commitment)| (tx_out.clone(), amount))
                        .ok()
                })
                .expect("Didn't find burn output");

            assert_eq!(burn_amount.value, 100_000);

            let ss = get_tx_out_shared_secret(
                &burn_address_view_private(),
                &RistrettoPublic::try_from(&burn_tx_out.public_key).unwrap(),
            );
            let memo = burn_tx_out.e_memo.unwrap().decrypt(&ss);
            assert_matches!(MemoType::try_from(&memo).expect("Couldn't decrypt memo"), MemoType::BurnRedemption(memo) if memo.memo_data() == &[5u8; 64]);
        }

        // Invalid memo data length results in an error.
        {
            let mut request = request.clone();
            request.redemption_memo = vec![5u8; BurnRedemptionMemo::MEMO_DATA_LEN + 1];
            assert!(client.generate_burn_redemption_tx(&request).is_err());
        }

        // Trying to burn more than we have results in an error.
        {
            let mut request = request.clone();
            request.burn_amount = 1_000_000_000_000 - request.fee + 1;
            assert!(client.generate_burn_redemption_tx(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_get_block_index_by_tx_pub_key(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Grab the first TxOut of each block in the database and verify its index.
        for block_index in 0..test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS as u64 {
            let block_contents = ledger_db.get_block_contents(block_index).unwrap();
            let tx_out_pub_key =
                api::external::CompressedRistretto::from(&block_contents.outputs[0].public_key);

            let request = api::GetBlockIndexByTxPubKeyRequest {
                tx_public_key: Some(tx_out_pub_key),
            };

            let response = client.get_block_index_by_tx_pub_key(&request).unwrap();
            assert_eq!(block_index, response.block);
        }
    }

    #[test_with_logger]
    /// Should return a correct proof-of-membership for each requested TxOut.
    fn test_get_tx_out_results_by_pub_key(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(sender.clone(), 0, 20, 0, "").unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Select some outputs from the ledger.
        let outputs: Vec<TxOut> = {
            let unspent_outputs = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();

            vec![
                unspent_outputs[1].tx_out.clone(),
                unspent_outputs[3].tx_out.clone(),
                unspent_outputs[5].tx_out.clone(),
            ]
        };

        // Send request for 3 known tx outs and 1 unknown key
        let request = api::GetTxOutResultsByPubKeyRequest {
            tx_out_public_keys: vec![
                (&outputs[0].public_key).into(),
                (&outputs[1].public_key).into(),
                (&outputs[2].public_key).into(),
                (&CompressedRistrettoPublic::from(RistrettoPublic::from_random(&mut rng))).into(),
            ],
        };

        let response = client.get_tx_out_results_by_pub_key(&request).unwrap();

        assert_eq!(response.results.len(), request.tx_out_public_keys.len());

        for i in 0..3 {
            assert_eq!(
                response.results[i].tx_out_pubkey.as_ref().unwrap(),
                &request.tx_out_public_keys[i]
            );
            assert_eq!(response.results[i].result_code(), TxOutResultCode::Found);
        }

        assert_eq!(
            response.results[3].tx_out_pubkey.as_ref().unwrap(),
            &request.tx_out_public_keys[3]
        );
        assert_eq!(response.results[3].result_code(), TxOutResultCode::NotFound);

        assert_eq!(
            Block::try_from(response.latest_block.as_ref().unwrap()).unwrap(),
            ledger_db.get_latest_block().unwrap()
        );
    }

    #[test_with_logger]
    fn test_generate_transfer_code_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Call generate transfer code ctx.
        let request = api::GenerateTransferCodeTxRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos.iter().map(api::UnspentTxOut::from).collect(),
            value: 1337,
            ..Default::default()
        };

        let response = client.generate_transfer_code_tx(&request).unwrap();

        // Test that the generated transaction can be picked up by mobilecoind.
        {
            let tx_proposal = TxProposal::try_from(response.tx_proposal.as_ref().unwrap()).unwrap();
            let key_images = tx_proposal.tx.key_images();
            let outputs = tx_proposal.tx.prefix.outputs;
            add_txos_and_key_images_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                outputs,
                key_images,
                &mut rng,
            )
            .unwrap();

            // Use bip39 entropy to construct AccountKey.
            let mnemonic =
                Mnemonic::from_entropy(response.bip39_entropy.as_slice(), Language::English)
                    .unwrap();
            let key = mnemonic.derive_slip10_key(0);
            let account_key = AccountKey::from(key);

            // Add a monitor based on the entropy we received.
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
                "",                       // name
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the new account and verify we only have one utxo.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            let utxo = &utxos[0];

            assert_eq!(utxo.value, 1337);
            assert_eq!(
                utxo.tx_out.public_key,
                RistrettoPublic::try_from(response.tx_public_key.as_ref().unwrap())
                    .unwrap()
                    .into()
            );
        }
    }

    #[test_with_logger]
    fn test_generate_optimization_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let sender_default_subaddress = sender.default_subaddress();
        let data = MonitorData::new(
            sender, 0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, and a bunch of random recipients and no monitors.
        // The random recipients are needed for mixins.
        let num_random_recipients = MAX_INPUTS as u32 * RING_SIZE as u32
            / test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS as u32;
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                num_random_recipients,
                &[sender_default_subaddress.clone()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Add a bunch of blocks/utxos for our recipient.
        for _ in 0..MAX_INPUTS {
            let _ = add_block_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                &[sender_default_subaddress.clone()],
                Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
                &[KeyImage::from(rng.next_u64())],
                &mut rng,
            );
        }

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Call generate optimization tx.
        let request = api::GenerateOptimizationTxRequest {
            monitor_id: monitor_id.to_vec(),
            subaddress: 0,
            ..Default::default()
        };

        let response = client.generate_optimization_tx(&request).unwrap();

        // Sanity test the response.
        let tx_proposal = TxProposal::try_from(response.tx_proposal.as_ref().unwrap()).unwrap();

        let expected_num_inputs: usize = MAX_INPUTS as usize;
        assert_eq!(tx_proposal.utxos.len(), expected_num_inputs);
        assert_eq!(tx_proposal.tx.prefix.inputs.len(), expected_num_inputs);

        assert_eq!(tx_proposal.outlays.len(), 1);
        assert_eq!(
            tx_proposal.outlays[0].receiver,
            data.account_key.subaddress(0)
        );
        assert_eq!(
            tx_proposal.outlays[0].amount.value,
            // Each UTXO we have has PER_RECIPIENT_AMOUNT coins. We will be merging MAX_INPUTS of
            // those into a single output, minus the fee.
            (DEFAULT_PER_RECIPIENT_AMOUNT * MAX_INPUTS) - Mob::MINIMUM_FEE,
        );
        assert_eq!(tx_proposal.outlays[0].amount.token_id, Mob::ID);

        assert_eq!(tx_proposal.outlay_index_to_tx_out_index.len(), 1);
        assert_eq!(tx_proposal.outlay_index_to_tx_out_index[&0], 0);

        assert_eq!(tx_proposal.tx.prefix.outputs.len(), 1);
        let tx_out = &tx_proposal.tx.prefix.outputs[0];
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
        let shared_secret =
            get_tx_out_shared_secret(data.account_key.view_private_key(), &tx_public_key);
        let (amount, _blinding) = tx_out
            .get_masked_amount()
            .unwrap()
            .get_value(&shared_secret)
            .unwrap();
        assert_eq!(amount.value, tx_proposal.outlays[0].amount.value);
        assert_eq!(amount.token_id, Mob::ID);

        // Santity test fee
        assert_eq!(tx_proposal.fee(), Mob::MINIMUM_FEE);
        assert_eq!(tx_proposal.tx.prefix.fee, Mob::MINIMUM_FEE);

        // Sanity test tombstone block
        let num_blocks = ledger_db.num_blocks().unwrap();
        assert_eq!(
            tx_proposal.tx.prefix.tombstone_block,
            num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
        );
    }

    #[test_with_logger]
    fn test_generate_tx_from_tx_out_list(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let _sender_default_subaddress = sender.default_subaddress();
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Build a request to transfer the first two TxOuts
        let tx_utxos = utxos[0..2].to_vec();
        let receiver = AccountKey::random(&mut rng);
        let request = api::GenerateTxFromTxOutListRequest {
            account_key: Some((&sender).into()),
            input_list: tx_utxos.iter().map(api::UnspentTxOut::from).collect(),
            receiver: Some((&receiver.default_subaddress()).into()),
            fee: Mob::MINIMUM_FEE,
            ..Default::default()
        };

        let response = client.generate_tx_from_tx_out_list(&request).unwrap();
        let tx_proposal = TxProposal::try_from(response.tx_proposal.as_ref().unwrap()).unwrap();

        // We should end up with one output
        assert_eq!(tx_proposal.tx.prefix.outputs.len(), 1);

        // It should equal the sum of the inputs minus the fee
        let expected_value = tx_utxos.iter().map(|utxo| utxo.value).sum::<u64>() - Mob::MINIMUM_FEE;

        let tx_out = &tx_proposal.tx.prefix.outputs[0];
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
        let shared_secret = get_tx_out_shared_secret(receiver.view_private_key(), &tx_public_key);
        let (amount, _blinding) = tx_out
            .get_masked_amount()
            .unwrap()
            .get_value(&shared_secret)
            .unwrap();
        assert_eq!(amount.value, expected_value);
        assert_eq!(amount.token_id, Mob::ID);
    }

    #[test_with_logger]
    fn test_submit_tx(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call generate tx.
        let request = api::GenerateTxRequest {
            sender_monitor_id: monitor_id.to_vec(),
            change_subaddress: 0,
            input_list: utxos.iter().map(api::UnspentTxOut::from).collect(),
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        // Get our propsal which we'll use for the test.
        let response = client.generate_tx(&request).unwrap();
        let tx_proposal = TxProposal::try_from(response.tx_proposal.as_ref().unwrap()).unwrap();
        let tx = tx_proposal.tx.clone();
        let outlay_confirmation_numbers = tx_proposal.outlay_confirmation_numbers.clone();

        // Test the happy flow.
        {
            let request = api::SubmitTxRequest {
                tx_proposal: Some(api::TxProposal::from(&tx_proposal)),
            };

            let response = client.submit_tx(&request).unwrap();

            // Get the submitted transaction - it was submitted to one of our mock peers,
            // but we don't know to which. We enforce the invariant that only
            // one transaction should've been submitted.
            let mut opt_submitted_tx: Option<Tx> = None;
            for mock_peer in server_conn_manager.conns() {
                let inner = mock_peer.read();
                match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                    (0, _) => {
                        // Nothing submitted to the current peer.
                    }
                    (1, None) => {
                        // Found our tx.
                        opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                    }
                    (1, Some(_)) => {
                        panic!("Tx submitted to two peers?!");
                    }
                    (_, _) => {
                        panic!("Multiple transactions submitted?!");
                    }
                }
            }
            let submitted_tx = opt_submitted_tx.unwrap();
            assert_eq!(tx, submitted_tx);

            // Sanity test sender receipt
            let key_images: Vec<KeyImage> = response
                .sender_tx_receipt
                .as_ref()
                .unwrap()
                .key_image_list
                .iter()
                .map(|key_image| KeyImage::try_from(key_image).unwrap())
                .collect();
            assert_eq!(key_images.len(), tx.prefix.inputs.len());

            for key_image in key_images.iter() {
                let subaddress_id = mobilecoind_db
                    .get_subaddress_id_by_utxo_id(&UtxoId::from(key_image))
                    .unwrap();
                assert_eq!(subaddress_id.monitor_id, monitor_id);
            }

            assert_eq!(
                response.sender_tx_receipt.as_ref().unwrap().tombstone,
                tx.prefix.tombstone_block
            );

            // Sanity the receiver receipts.
            assert_eq!(response.receiver_tx_receipt_list.len(), outlays.len());
            for (outlay, receipt) in outlays.iter().zip(response.receiver_tx_receipt_list.iter()) {
                assert_eq!(
                    outlay.receiver,
                    PublicAddress::try_from(receipt.recipient.as_ref().unwrap()).unwrap()
                );

                assert_eq!(receipt.tombstone, tx.prefix.tombstone_block);
                let mut confirmation_bytes = [0u8; 32];
                confirmation_bytes.copy_from_slice(&receipt.confirmation_number);

                let confirmation_number = TxOutConfirmationNumber::from(confirmation_bytes);
                assert!(outlay_confirmation_numbers.contains(&confirmation_number));
            }

            assert_eq!(
                response.receiver_tx_receipt_list.len() + 1, /* There's a change output
                                                              * that is not part of the
                                                              * receipts */
                tx.prefix.outputs.len()
            );

            let tx_out_hashes: Vec<_> = tx.prefix.outputs.iter().map(TxOut::hash).collect();
            let tx_out_public_keys: Vec<_> = tx
                .prefix
                .outputs
                .iter()
                .map(|tx_out| tx_out.public_key.to_bytes())
                .collect();

            for receipt in response.receiver_tx_receipt_list.iter() {
                let hash: [u8; 32] = receipt.tx_out_hash.as_slice().try_into().unwrap();
                assert!(tx_out_hashes.contains(&hash));

                let public_key = GenericArray::<u8, U32>::from_slice(
                    receipt.tx_public_key.as_ref().unwrap().data.as_slice(),
                );
                assert!(tx_out_public_keys.contains(public_key));
            }

            // Check that attempted_spend_height got updated for the relevant utxos.
            let account_utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();
            let tx_proposal_utxo_ids: Vec<UtxoId> =
                tx_proposal.utxos.iter().map(UtxoId::from).collect();
            let mut matched_utxos = 0;
            for utxo in account_utxos.iter() {
                if tx_proposal_utxo_ids.contains(&UtxoId::from(utxo)) {
                    assert!(utxo.attempted_spend_height > 0);
                    matched_utxos += 1;
                } else {
                    assert_eq!(utxo.attempted_spend_height, 0);
                }
            }
            assert_eq!(matched_utxos, tx_proposal.utxos.len());
        }
    }

    #[test_with_logger]
    fn test_get_balance_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let account_key = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            account_key.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[account_key.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get balance for a monitor_id/subaddress index that has a balance.
        let request = api::GetBalanceRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client.get_balance(&request).unwrap();
        assert_eq!(
            response.balance,
            test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * ledger_db.num_blocks().unwrap()
        );

        // Get balance for subaddress with no utxos should return 0.
        let request = api::GetBalanceRequest {
            monitor_id: id.to_vec(),
            subaddress_index: 1,
            ..Default::default()
        };

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, 0);

        // Non-existent monitor id should return 0
        let mut id2 = id.clone().to_vec();
        id2[0] = !id2[0];

        let request = api::GetBalanceRequest {
            monitor_id: id2,
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, 0);

        // Invalid monitor id should error
        let request = api::GetBalanceRequest {
            monitor_id: vec![1; 2],
            subaddress_index: 0,
            ..Default::default()
        };

        assert!(client.get_balance(&request).is_err());
    }

    #[test_with_logger]
    fn test_send_payment(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call send payment.
        let request = api::SendPaymentRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        let response = client.send_payment(&request).unwrap();

        // Get the submitted transaction - it was submitted to one of our mock peers,
        // but we don't know to which. We enforce the invariant that only one
        // transaction should've been submitted.
        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }
        let submitted_tx = opt_submitted_tx.unwrap();
        assert_eq!(
            submitted_tx,
            Tx::try_from(response.tx_proposal.as_ref().unwrap().tx.as_ref().unwrap()).unwrap()
        );

        // Sanity test sender receipt
        let key_images: Vec<KeyImage> = response
            .sender_tx_receipt
            .as_ref()
            .unwrap()
            .key_image_list
            .iter()
            .map(|key_image| KeyImage::try_from(key_image).unwrap())
            .collect();
        assert_eq!(key_images.len(), submitted_tx.prefix.inputs.len());

        for key_image in key_images.iter() {
            let subaddress_id = mobilecoind_db
                .get_subaddress_id_by_utxo_id(&UtxoId::from(key_image))
                .unwrap();
            assert_eq!(subaddress_id.monitor_id, monitor_id);
        }

        assert_eq!(
            response.sender_tx_receipt.as_ref().unwrap().tombstone,
            submitted_tx.prefix.tombstone_block
        );

        // Sanity the receiver receipts.
        assert_eq!(response.receiver_tx_receipt_list.len(), outlays.len());
        for (outlay, receipt) in outlays.iter().zip(response.receiver_tx_receipt_list.iter()) {
            assert_eq!(
                outlay.receiver,
                PublicAddress::try_from(receipt.recipient.as_ref().unwrap()).unwrap()
            );

            assert_eq!(receipt.tombstone, submitted_tx.prefix.tombstone_block);
        }

        assert_eq!(
            response.receiver_tx_receipt_list.len() + 1, /* There's a change output that
                                                          * is not part of the receipts */
            submitted_tx.prefix.outputs.len()
        );

        let tx_out_hashes: Vec<_> = submitted_tx
            .prefix
            .outputs
            .iter()
            .map(TxOut::hash)
            .collect();
        let tx_out_public_keys: Vec<_> = submitted_tx
            .prefix
            .outputs
            .iter()
            .map(|tx_out| tx_out.public_key.to_bytes())
            .collect();

        for receipt in response.receiver_tx_receipt_list.iter() {
            let hash: [u8; 32] = receipt.tx_out_hash.as_slice().try_into().unwrap();
            assert!(tx_out_hashes.contains(&hash));

            let public_key = GenericArray::<u8, U32>::from_slice(
                receipt.tx_public_key.as_ref().unwrap().data.as_slice(),
            );
            assert!(tx_out_public_keys.contains(public_key));
        }

        // Check that attempted_spend_height got updated for the relevant utxos.
        let tx_proposal = TxProposal::try_from(response.tx_proposal.as_ref().unwrap()).unwrap();

        let account_utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        let tx_proposal_utxo_ids: Vec<UtxoId> =
            tx_proposal.utxos.iter().map(UtxoId::from).collect();
        let mut matched_utxos = 0;
        for utxo in account_utxos.iter() {
            if tx_proposal_utxo_ids.contains(&UtxoId::from(utxo)) {
                assert!(utxo.attempted_spend_height > 0);
                matched_utxos += 1;
            } else {
                assert_eq!(utxo.attempted_spend_height, 0);
            }
        }
        assert_eq!(matched_utxos, tx_proposal.utxos.len());
    }

    #[test_with_logger]
    fn test_send_payment_with_max_input_utxo_value(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 10, &[], &[], logger.clone(), &mut rng);

        // Add a few utxos to our recipient, such that all of them are required to
        // create the test transaction.
        for amount in &[10, 20, Mob::MINIMUM_FEE] {
            add_block_to_ledger(
                &mut ledger_db,
                BLOCK_VERSION,
                &[sender.default_subaddress()],
                Amount::new(*amount, Mob::ID),
                &[KeyImage::from(rng.next_u64())],
                &mut rng,
            )
            .unwrap();
        }

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        let utxos_by_keyimage: HashMap<KeyImage, UnspentTxOut> = utxos
            .iter()
            .map(|utxo| (utxo.key_image, utxo.clone()))
            .collect();

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random(&mut rng);

        let outlays = vec![
            Outlay {
                value: 10,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 20,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call send payment without a limit on UTXOs - a single large UTXO should be
        // selected.
        let mut request = api::SendPaymentRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        let response = client.send_payment(&request).unwrap();

        // Check which UTXOs were selected - it should be all of them.
        let selected_utxos: Vec<UnspentTxOut> = response
            .sender_tx_receipt
            .as_ref()
            .unwrap()
            .key_image_list
            .iter()
            .map(|proto_key_image| {
                let key_image = KeyImage::try_from(proto_key_image).unwrap();
                utxos_by_keyimage.get(&key_image).unwrap().clone()
            })
            .collect();
        assert_eq!(
            HashSet::from_iter(selected_utxos),
            HashSet::from_iter(utxos.clone())
        );

        // Try again, placing a cap at the max UTXO that can be selected. This should
        // cause send payment to fail.
        request.max_input_utxo_value = 20;
        match client.send_payment(&request) {
            Ok(_) => panic!("Should've returned an error"),
            Err(GrpcError::RpcFailure(rpc_status)) => {
                assert_eq!(
                    rpc_status.message(),
                    "transactions_manager.build_transaction: Insufficient funds".to_owned()
                );
            }
            Err(err) => panic!("Unexpected error: {err:?}"),
        };

        // Trying with a higher limit should work.
        request.max_input_utxo_value = Mob::MINIMUM_FEE;
        let response = client.send_payment(&request).unwrap();

        let selected_utxos: Vec<UnspentTxOut> = response
            .sender_tx_receipt
            .as_ref()
            .unwrap()
            .key_image_list
            .iter()
            .map(|proto_key_image| {
                let key_image = KeyImage::try_from(proto_key_image).unwrap();
                utxos_by_keyimage.get(&key_image).unwrap().clone()
            })
            .collect();
        assert_eq!(
            HashSet::from_iter(selected_utxos),
            HashSet::from_iter(utxos)
        );
    }

    #[test_with_logger]
    fn test_send_payment_to_fog(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // Fog resolver
        let fog_private_key = RistrettoPrivate::from_random(&mut rng);
        let fog_pubkey_resolver_factory: Arc<
            dyn Fn(&[FogUri]) -> Result<MockFogPubkeyResolver, String> + Send + Sync,
        > = Arc::new(move |_| -> Result<MockFogPubkeyResolver, String> {
            let mut fog_pubkey_resolver = MockFogPubkeyResolver::new();
            let pubkey = RistrettoPublic::from(&fog_private_key);
            fog_pubkey_resolver
                .expect_get_fog_pubkey()
                .return_once(move |_recipient| {
                    Ok(FullyValidatedFogPubkey {
                        pubkey,
                        pubkey_expiry: 10000,
                    })
                });
            Ok(fog_pubkey_resolver)
        });

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db) = test_utils::get_test_databases(
            BLOCK_VERSION,
            3,
            &[sender.default_subaddress()],
            test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS,
            logger.clone(),
            &mut rng,
        );
        let port = test_utils::get_free_port();

        let uri =
            MobilecoindUri::from_str(&format!("insecure-mobilecoind://127.0.0.1:{port}/")).unwrap();

        log::debug!(logger, "Setting up server {:?}", port);
        let (_server, server_conn_manager) = test_utils::setup_server::<MockFogPubkeyResolver>(
            logger.clone(),
            ledger_db.clone(),
            mobilecoind_db.clone(),
            None,
            Some(fog_pubkey_resolver_factory),
            &uri,
        );
        log::debug!(logger, "Setting up client {:?}", port);
        let client = test_utils::setup_client(&uri, &logger);

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random_with_fog(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call send payment.
        let request = api::SendPaymentRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        let response = client.send_payment(&request).unwrap();

        // Get the submitted transaction - it was submitted to one of our mock peers,
        // but we don't know to which. We enforce the invariant that only one
        // transaction should've been submitted.
        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }
        let submitted_tx = opt_submitted_tx.unwrap();
        assert_eq!(
            submitted_tx,
            Tx::try_from(response.tx_proposal.as_ref().unwrap().tx.as_ref().unwrap()).unwrap()
        );

        // Verify that the first receipient TxOut hint cannot be decrypted with the fog
        // key, since that one was not going to a fog address.
        let tx_out_index1 = *(response
            .tx_proposal
            .as_ref()
            .unwrap()
            .outlay_index_to_tx_out_index
            .get(&0)
            .unwrap()) as usize;
        let tx_out1 = submitted_tx.prefix.outputs.get(tx_out_index1).unwrap();
        let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
        assert!(!bool::from(FogHint::ct_decrypt(
            &fog_private_key,
            &tx_out1.e_fog_hint,
            &mut output_fog_hint
        )));

        // The second recipient (the fog recipient) should have a valid hint.
        let tx_out_index2 = *(response
            .tx_proposal
            .as_ref()
            .unwrap()
            .outlay_index_to_tx_out_index
            .get(&1)
            .unwrap()) as usize;
        let tx_out2 = submitted_tx.prefix.outputs.get(tx_out_index2).unwrap();
        let mut output_fog_hint = FogHint::new(RistrettoPublic::from_random(&mut rng));
        assert!(bool::from(FogHint::ct_decrypt(
            &fog_private_key,
            &tx_out2.e_fog_hint,
            &mut output_fog_hint
        )));
        assert_eq!(
            output_fog_hint.get_view_pubkey(),
            &CompressedRistrettoPublic::from(receiver2.default_subaddress().view_public_key())
        );
    }

    #[test_with_logger]
    fn test_send_payment_to_fog_fails_without_fog_resolver(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate two random recipients.
        let receiver1 = AccountKey::random(&mut rng);
        let receiver2 = AccountKey::random_with_fog(&mut rng);

        let outlays = vec![
            Outlay {
                value: 123,
                receiver: receiver1.default_subaddress(),
                tx_private_key: None,
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
                tx_private_key: None,
            },
        ];

        // Call send payment.
        let request = api::SendPaymentRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            outlay_list: outlays.iter().map(api::Outlay::from).collect(),
            ..Default::default()
        };

        let response = client.send_payment(&request);
        assert!(response.is_err());
    }

    #[test_with_logger]
    fn test_pay_address_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate a random recipient.
        let receiver = AccountKey::random(&mut rng);

        // Generate b58 address code for this recipient.
        let receiver_public_address = receiver.default_subaddress();
        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&receiver_public_address).into(),
            )),
        };
        let b58_code = wrapper.b58_encode().unwrap();

        // Call pay address code.
        let request = api::PayAddressCodeRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            receiver_b58_code: b58_code.clone(),
            amount: 1234,
            ..Default::default()
        };

        let response = client.pay_address_code(&request).unwrap();

        // Sanity the receiver receipt.
        assert_eq!(response.receiver_tx_receipt_list.len(), 1);

        let receipt = &response.receiver_tx_receipt_list[0];
        assert_eq!(
            receipt.recipient.as_ref().unwrap(),
            &api::external::PublicAddress::from(&receiver_public_address)
        );
    }

    #[test_with_logger]
    fn test_pay_address_code_alternate_change(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let monitor_id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get list of unspent tx outs
        let utxos = mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, 0)
            .unwrap();
        assert!(!utxos.is_empty());

        // Generate a random recipient.
        let receiver = AccountKey::random(&mut rng);

        // Generate b58 address code for this recipient.
        let receiver_public_address = receiver.default_subaddress();
        let wrapper = api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&receiver_public_address).into(),
            )),
        };
        let b58_code = wrapper.b58_encode().unwrap();

        let test_amount = 345;

        // Explicitly set fee so we can check change amount
        let fee = 1000;
        let request = api::PayAddressCodeRequest {
            sender_monitor_id: monitor_id.to_vec(),
            sender_subaddress: 0,
            receiver_b58_code: b58_code.clone(),
            amount: test_amount,
            override_change_subaddress: true,
            change_subaddress: 1,
            fee,
            ..Default::default()
        };

        let response = client.pay_address_code(&request).unwrap();
        let total_value = response
            .tx_proposal
            .as_ref()
            .unwrap()
            .input_list
            .iter()
            .map(|utxo| utxo.value)
            .sum::<u64>();

        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.proposed_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.proposed_txs[0].clone())
                }
                (1, Some(_)) => {
                    panic!("Tx submitted to two peers?!");
                }
                (_, _) => {
                    panic!("Multiple transactions submitted?!");
                }
            }
        }

        let submitted_tx = opt_submitted_tx.unwrap();
        let mut change_subaddress_found = false;
        for tx_out in submitted_tx.prefix.outputs {
            let tx_out_target_key = RistrettoPublic::try_from(&tx_out.target_key).unwrap();
            let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();

            let subaddress_spk = SubaddressSPKId::from(&recover_public_subaddress_spend_key(
                sender.view_private_key(),
                &tx_out_target_key,
                &tx_public_key,
            ));

            match mobilecoind_db.get_subaddress_id_by_spk(&subaddress_spk) {
                Ok(data) => {
                    if data.index == 1 {
                        assert!(!change_subaddress_found);
                        change_subaddress_found = true;
                        let shared_secret =
                            get_tx_out_shared_secret(sender.view_private_key(), &tx_public_key);

                        let (amount, _blinding) = tx_out
                            .get_masked_amount()
                            .unwrap()
                            .get_value(&shared_secret)
                            .expect("Malformed amount");

                        assert_eq!(total_value - test_amount - fee, amount.value);
                        assert_eq!(amount.token_id, Mob::ID);
                    }
                }
                Err(Error::SubaddressSPKNotFound) => continue,
                Err(_err) => {
                    panic!("Error matching subaddress");
                }
            };
        }

        assert!(change_subaddress_found);
    }

    #[test_with_logger]
    fn test_request_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        // Random receiver address.
        let receiver = AccountKey::random(&mut rng).default_subaddress();

        // Try with just a receiver
        {
            // Generate a request code
            let request = api::CreateRequestCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
                ..Default::default()
            };

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode the b58.
            let request = api::ParseRequestCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 0);
            assert_eq!(response.memo, "");
        }
        // Try with receiver and value
        {
            // Generate a request code
            let request = api::CreateRequestCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
                value: 1234567890,
                ..Default::default()
            };

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode it.
            let request = api::ParseRequestCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.memo, "");
        }
        // Try with receiver, value and memo
        {
            // Generate a request code
            let request = api::CreateRequestCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
                value: 1234567890,
                memo: "hello there".to_owned(),
                ..Default::default()
            };

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode it.
            let request = api::ParseRequestCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.memo, "hello there");
        }

        // Try with receiver, value and token id.
        {
            // Generate a request code
            let request = api::CreateRequestCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
                value: 1234567890,
                token_id: 123,
                ..Default::default()
            };

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode it.
            let request = api::ParseRequestCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.token_id, 123);
        }

        // Attempting to decode junk data should fail
        {
            let request = api::ParseRequestCodeRequest {
                b58_code: "junk".to_owned(),
            };

            assert!(client.parse_request_code(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_transfer_code_root_entropy(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger.clone(), &mut rng);

        // a valid transfer code must reference a tx_public_key that appears in the
        // ledger that is controlled by the root_entropy included in the code

        let root_entropy = [3u8; 32];

        // Use root entropy to construct AccountKey.
        let root_id = RootIdentity::from(&root_entropy);
        let account_key = AccountKey::from(&root_id);

        let (tx_out, _) = create_tx_out(
            Amount::new(10, Mob::ID),
            &account_key.subaddress(DEFAULT_SUBADDRESS_INDEX),
            &mut rng,
        );

        add_txos_to_ledger(&mut ledger_db, BLOCK_VERSION, &[tx_out.clone()], &mut rng).unwrap();

        let tx_public_key = tx_out.public_key;

        // An invalid request should fail to encode.
        {
            let request = api::CreateTransferCodeRequest {
                root_entropy: vec![3u8; 8], // key is wrong size
                tx_public_key: Some((&tx_public_key).into()),
                memo: "memo".to_owned(),
                ..Default::default()
            };
            assert!(client.create_transfer_code(&request).is_err());

            let request = api::CreateTransferCodeRequest {
                root_entropy: vec![4u8; 32],
                memo: "memo".to_owned(),
                ..Default::default() // forgot to set tx_public_key
            };
            assert!(client.create_transfer_code(&request).is_err());

            // no entropy is being set
            let request = api::CreateTransferCodeRequest {
                tx_public_key: Some((&tx_public_key).into()),
                memo: "memo".to_owned(),
                ..Default::default()
            };
            assert!(client.create_transfer_code(&request).is_err());
        }

        // A valid request should allow us to encode to b58 and back to the original
        // data.
        {
            // Encode
            let request = api::CreateTransferCodeRequest {
                root_entropy: root_entropy.to_vec(),
                tx_public_key: Some((&tx_public_key).into()),
                memo: "test memo".to_owned(),
                ..Default::default()
            };

            let response = client.create_transfer_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Decode
            let request = api::ParseTransferCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_transfer_code(&request).unwrap();

            // Compare
            assert_eq!(&root_entropy, response.root_entropy.as_slice());
            assert!(response.bip39_entropy.is_empty());
            assert_eq!(
                tx_public_key,
                CompressedRistrettoPublic::try_from(response.tx_public_key.as_ref().unwrap())
                    .unwrap()
            );
            assert_eq!(response.memo, "test memo");

            // check that the utxo that comes back from the code matches the ledger data

            // Add a monitor based on the entropy we received.
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
                "",                       // name
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the account and verify a match utxo.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            // Convert to proto utxo.
            let proto_utxo: api::UnspentTxOut = (&utxos[0]).into();

            assert_eq!(&proto_utxo, response.utxo.as_ref().unwrap());
        }
    }

    #[test_with_logger]
    fn test_transfer_code_bip39_entropy(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger.clone(), &mut rng);

        // a valid transfer code must reference a tx_public_key that appears in the
        // ledger that is controlled by the bip39_entropy included in the code
        let bip39_entropy = [4u8; 32];

        // Use bip39 entropy to construct AccountKey.
        let mnemonic = Mnemonic::from_entropy(&bip39_entropy, Language::English).unwrap();
        let key = mnemonic.derive_slip10_key(0);
        let account_key = AccountKey::from(key);

        let (tx_out, _) = create_tx_out(
            Amount::new(10, Mob::ID),
            &account_key.subaddress(DEFAULT_SUBADDRESS_INDEX),
            &mut rng,
        );

        add_txos_to_ledger(&mut ledger_db, BLOCK_VERSION, &[tx_out.clone()], &mut rng).unwrap();

        let tx_public_key = tx_out.public_key;

        // An invalid request should fail to encode.
        {
            let request = api::CreateTransferCodeRequest {
                bip39_entropy: vec![3u8; 8], // key is wrong size
                tx_public_key: Some((&tx_public_key).into()),
                memo: "memo".to_owned(),
                ..Default::default()
            };
            assert!(client.create_transfer_code(&request).is_err());

            let request = api::CreateTransferCodeRequest {
                bip39_entropy: vec![4u8; 32],
                memo: "memo".to_owned(), // forgot to set tx_public_key
                ..Default::default()
            };
            assert!(client.create_transfer_code(&request).is_err());
        }

        // A valid request should allow us to encode to b58 and back to the original
        // data.
        {
            // Encode
            let request = api::CreateTransferCodeRequest {
                bip39_entropy: bip39_entropy.to_vec(),
                tx_public_key: Some((&tx_public_key).into()),
                memo: "test memo".to_owned(),
                ..Default::default()
            };

            let response = client.create_transfer_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Decode
            let request = api::ParseTransferCodeRequest {
                b58_code: b58_code.clone(),
            };

            let response = client.parse_transfer_code(&request).unwrap();

            // Compare
            assert_eq!(&bip39_entropy, response.bip39_entropy.as_slice());
            assert!(response.root_entropy.is_empty());
            assert_eq!(
                tx_public_key,
                CompressedRistrettoPublic::try_from(response.tx_public_key.as_ref().unwrap())
                    .unwrap()
            );
            assert_eq!(response.memo, "test memo");

            // check that the utxo that comes back from the code matches the ledger data

            // Add a monitor based on the entropy we received.
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
                "",                       // name
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the account and verify a match utxo.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, DEFAULT_SUBADDRESS_INDEX)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            // Convert to proto utxo.
            let proto_utxo: api::UnspentTxOut = (&utxos[0]).into();

            assert_eq!(&proto_utxo, response.utxo.as_ref().unwrap());
        }
    }

    #[test_with_logger]
    fn test_address_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        {
            // Random receiver address.
            let receiver = AccountKey::random(&mut rng).default_subaddress();

            // Generate a request code
            let request = api::CreateAddressCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
            };

            let response = client.create_address_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode it.
            let request = api::ParseAddressCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_address_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
        }

        // Also accept a payment request code as an address code
        {
            // Random receiver address.
            let receiver = AccountKey::random(&mut rng).default_subaddress();

            // Generate a request code
            let request = api::CreateRequestCodeRequest {
                receiver: Some(mc_api::external::PublicAddress::from(&receiver)),
                value: 1234567890,
                memo: "hello there".to_owned(),
                ..Default::default()
            };

            let response = client.create_request_code(&request).unwrap();
            let b58_code = response.b58_code;

            // Attempt to decode it.
            let request = api::ParseAddressCodeRequest {
                b58_code: b58_code.to_string(),
            };

            let response = client.parse_address_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.receiver.as_ref().unwrap()).unwrap(),
                receiver
            );
        }

        // Attempting to decode junk data should fail
        {
            let request = api::ParseAddressCodeRequest {
                b58_code: "junk".to_owned(),
            };

            assert!(client.parse_address_code(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_get_network_status(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(BLOCK_VERSION, 3, &[], &[], logger, &mut rng);

        let network_status = client.get_network_status(&()).unwrap();

        assert_eq!(
            network_status.network_highest_block_index,
            ledger_db.num_blocks().unwrap() - 1
        );

        assert_eq!(
            network_status.local_block_index,
            ledger_db.num_blocks().unwrap() - 1
        );
    }

    #[test_with_logger]
    fn test_add_remove_add_monitor_with_spent_key_images(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        let sender = AccountKey::random(&mut rng);
        let data = MonitorData::new(
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
            "", // name
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger.clone(),
                &mut rng,
            );

        let request = api::AddMonitorRequest {
            account_key: Some((&data.account_key).into()),
            first_subaddress: data.first_subaddress,
            num_subaddresses: data.num_subaddresses,
            first_block: data.first_block,
            ..Default::default()
        };

        // Send request.
        let response = client.add_monitor(&request).expect("failed to add monitor");
        let monitor_id = response.monitor_id;

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have the expected balance.
        let request = api::GetBalanceRequest {
            monitor_id: monitor_id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client.get_balance(&request).unwrap();
        assert_eq!(
            response.balance,
            test_utils::DEFAULT_PER_RECIPIENT_AMOUNT * ledger_db.num_blocks().unwrap()
        );
        let orig_balance = response.balance;

        // Get our UTXOs and force one of them to be spent, since we want to test the
        // add-remove-add behavior with spent key images in the ledger.
        let request = api::GetUnspentTxOutListRequest {
            monitor_id: monitor_id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        let first_utxo = response.output_list[0].clone();
        let first_key_image = KeyImage::try_from(first_utxo.key_image.as_ref().unwrap())
            .expect("failed covnerting proto keyimage");

        let recipient = AccountKey::random(&mut rng).default_subaddress();
        add_block_to_ledger(
            &mut ledger_db,
            BLOCK_VERSION,
            &[recipient],
            Amount::new(DEFAULT_PER_RECIPIENT_AMOUNT, Mob::ID),
            &[first_key_image],
            &mut rng,
        )
        .unwrap();

        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have the expected balance.
        let request = api::GetBalanceRequest {
            monitor_id: monitor_id.to_vec(),
            subaddress_index: 0,
            ..Default::default()
        };

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, orig_balance - first_utxo.value);

        // Verify we have processed block information for this monitor.
        let request = api::GetProcessedBlockRequest {
            monitor_id: monitor_id.to_vec(),
            block: 0,
        };

        let response = client
            .get_processed_block(&request)
            .expect("Failed getting processed block");
        assert_eq!(response.tx_outs.len(), 1);

        // Remove the monitor.
        let request = api::RemoveMonitorRequest {
            monitor_id: monitor_id.to_vec(),
        };
        client
            .remove_monitor(&request)
            .expect("failed to remove monitor");

        // Check that no monitors remain.
        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(0, monitors_map.len());

        // Verify we no longer have processed block information for this monitor.
        let request = api::GetProcessedBlockRequest {
            monitor_id: monitor_id.to_vec(),
            block: 0,
        };

        assert!(client.get_processed_block(&request).is_err());

        // Re-add the monitor.
        let request = api::AddMonitorRequest {
            account_key: Some((&data.account_key).into()),
            first_subaddress: data.first_subaddress,
            num_subaddresses: data.num_subaddresses,
            first_block: data.first_block,
            ..Default::default()
        };

        let response = client.add_monitor(&request).expect("failed to add monitor");
        assert_eq!(monitor_id, response.monitor_id);

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Verify we have processed block information for this monitor.
        let request = api::GetProcessedBlockRequest {
            monitor_id: monitor_id.to_vec(),
            block: 0,
        };

        let response = client
            .get_processed_block(&request)
            .expect("Failed getting processed block");
        assert_eq!(response.tx_outs.len(), 1);
    }

    #[test_with_logger]
    fn test_get_version(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);
        let sender = AccountKey::random(&mut rng);

        // 1 known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                BLOCK_VERSION,
                3,
                &[sender.default_subaddress()],
                &[],
                logger,
                &mut rng,
            );

        // Send request.
        let response = client.get_version(&()).expect("Failed to get version");
        assert!(!response.version.is_empty());
    }
}
