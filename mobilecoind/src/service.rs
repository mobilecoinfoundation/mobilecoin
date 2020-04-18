// Copyright (c) 2018-2020 MobileCoin Inc.

//! The mobilecoind Service
//! * provides a GRPC server
//! * creates a managing thread and thread pool that scans a local database
//! * processes all transactions to discover transactions for monitors
//! * writes matching transactions to a local DB, organized by subaddress_id

use crate::{
    database::Database,
    error::Error,
    monitor_store::{MonitorData, MonitorId},
    payments::{Outlay, TransactionsManager, TxProposal},
    sync::SyncThread,
    utxo_store::{UnspentTxOut, UtxoId},
};

use common::{
    logger::{log, Logger},
    HashMap,
};
use grpc_util::{rpc_internal_error, rpc_logger, send_result};
use grpcio::{RpcContext, RpcStatus, RpcStatusCode, UnarySink};
use keys::RistrettoPublic;
use ledger_db::{Ledger, LedgerDB};
use mc_b58_payloads::payloads::{RequestPayload, TransferPayload};
use mcconnection::UserTxConnection;
use mcserial::ReprBytes32;
use mobilecoind_api::mobilecoind_api_grpc::{create_mobilecoind_api, MobilecoindApi};
use protobuf::RepeatedField;
use std::{convert::TryFrom, sync::Arc};
use transaction::{
    account_keys::{AccountKey, PublicAddress},
    ring_signature::KeyImage,
};
use transaction_std::identity::RootIdentity;

pub struct Service {
    /// Sync thread.
    _sync_thread: SyncThread,

    /// GRPC server.
    _server: grpcio::Server,
}

impl Service {
    pub fn new<T: UserTxConnection + 'static>(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        transactions_manager: TransactionsManager<T>,
        port: u16,
        num_workers: Option<usize>,
        logger: Logger,
    ) -> Self {
        let env = Arc::new(
            grpcio::EnvBuilder::new()
                .name_prefix("Mobilecoind-RPC".to_string())
                .build(),
        );

        log::info!(logger, "Starting mobilecoind sync task thread");
        let sync_thread = SyncThread::start(
            ledger_db.clone(),
            mobilecoind_db.clone(),
            num_workers,
            logger.clone(),
        );

        let api = ServiceApi::new(
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            logger.clone(),
        );

        // Package it into grpc service
        let mobilecoind_service = create_mobilecoind_api(api);

        // Health check service
        let health_service = grpc_util::HealthService::new(None, logger.clone()).into_service();

        // Package service into grpc server
        log::info!(logger, "Starting mobilecoind API Service on port {}", port);
        let server = grpc_util::run_server(
            env,
            vec![mobilecoind_service, health_service],
            port,
            &logger,
        );

        Self {
            _server: server,
            _sync_thread: sync_thread,
        }
    }
}

pub struct ServiceApi<T: UserTxConnection + 'static> {
    transactions_manager: TransactionsManager<T>,
    ledger_db: LedgerDB,
    mobilecoind_db: Database,
    logger: Logger,
}

impl<T: UserTxConnection + 'static> Clone for ServiceApi<T> {
    fn clone(&self) -> Self {
        Self {
            transactions_manager: self.transactions_manager.clone(),
            ledger_db: self.ledger_db.clone(),
            mobilecoind_db: self.mobilecoind_db.clone(),
            logger: self.logger.clone(),
        }
    }
}

impl<T: UserTxConnection + 'static> ServiceApi<T> {
    pub fn new(
        transactions_manager: TransactionsManager<T>,
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        logger: Logger,
    ) -> Self {
        Self {
            transactions_manager,
            ledger_db,
            mobilecoind_db,
            logger,
        }
    }

    fn add_monitor_impl(
        &mut self,
        request: mobilecoind_api::AddMonitorRequest,
    ) -> Result<mobilecoind_api::AddMonitorResponse, RpcStatus> {
        // Get the AccountKey from the GRPC request.
        let proto_account_key = request.account_key.as_ref().ok_or_else(|| {
            RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("account_key".to_string()),
            )
        })?;
        let account_key = AccountKey::try_from(proto_account_key)
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // Populate a new `MonitorData` instance.
        let data = MonitorData::new(
            account_key,
            request.first_subaddress,
            request.num_subaddresses,
            request.first_block,
        )
        .map_err(|err| rpc_internal_error("monitor_data.new", err, &self.logger))?;

        // Insert into database. If the monitor already exists, we will simply return its id.
        let id = match self.mobilecoind_db.add_monitor(&data) {
            Ok(id) => Ok(id),
            Err(Error::MonitorIdExists) => Ok(MonitorId::from(&data)),
            Err(err) => Err(err),
        }
        .map_err(|err| rpc_internal_error("mobilecoind_db.add_monitor", err, &self.logger))?;

        // Return success response.
        let mut response = mobilecoind_api::AddMonitorResponse::new();
        response.set_monitor_id(id.to_vec());
        Ok(response)
    }

    fn remove_monitor_impl(
        &mut self,
        request: mobilecoind_api::RemoveMonitorRequest,
    ) -> Result<mobilecoind_api::Empty, RpcStatus> {
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
        let response = mobilecoind_api::Empty::new();
        Ok(response)
    }

    fn get_monitor_list_impl(
        &mut self,
        _request: mobilecoind_api::Empty,
    ) -> Result<mobilecoind_api::GetMonitorListResponse, RpcStatus> {
        let monitor_map: HashMap<MonitorId, MonitorData> =
            self.mobilecoind_db.get_monitor_map().map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_store_map", err, &self.logger)
            })?;

        let mut response = mobilecoind_api::GetMonitorListResponse::new();
        for id in monitor_map.keys() {
            response.mut_monitor_id_list().push(id.to_vec());
        }
        Ok(response)
    }

    fn get_monitor_status_impl(
        &mut self,
        request: mobilecoind_api::GetMonitorStatusRequest,
    ) -> Result<mobilecoind_api::GetMonitorStatusResponse, RpcStatus> {
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        let data = self
            .mobilecoind_db
            .get_monitor_data(&monitor_id)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_monitor_data", err, &self.logger)
            })?;

        let mut status = mobilecoind_api::MonitorStatus::new();
        status.set_account_key(mobilecoind_api::AccountKey::from(&data.account_key));
        status.set_first_subaddress(data.first_subaddress);
        status.set_num_subaddresses(data.num_subaddresses);
        status.set_first_block(data.first_block);
        status.set_next_block(data.next_block);

        let mut response = mobilecoind_api::GetMonitorStatusResponse::new();
        response.set_status(status);
        Ok(response)
    }

    fn get_unspent_tx_out_list_impl(
        &mut self,
        request: mobilecoind_api::GetUnspentTxOutListRequest,
    ) -> Result<mobilecoind_api::GetUnspentTxOutListResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get UnspentTxOuts.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&monitor_id, request.subaddress_index)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Convert to protos.
        let proto_utxos: Vec<mobilecoind_api::UnspentTxOut> =
            utxos.iter().map(|utxo| utxo.into()).collect();

        // Returrn response.
        let mut response = mobilecoind_api::GetUnspentTxOutListResponse::new();
        response.set_output_list(RepeatedField::from_vec(proto_utxos));
        Ok(response)
    }

    fn generate_entropy_impl(
        &mut self,
        _request: mobilecoind_api::Empty,
    ) -> Result<mobilecoind_api::GenerateEntropyResponse, RpcStatus> {
        let mut rng = rand::thread_rng();
        let root_id = RootIdentity::random(&mut rng, None);
        let mut response = mobilecoind_api::GenerateEntropyResponse::new();
        response.set_entropy(root_id.root_entropy.to_vec());
        Ok(response)
    }

    fn get_account_key_impl(
        &mut self,
        request: mobilecoind_api::GetAccountKeyRequest,
    ) -> Result<mobilecoind_api::GetAccountKeyResponse, RpcStatus> {
        // Get the entropy.
        if request.get_entropy().len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("entropy".to_string()),
            ));
        }
        let mut root_entropy = [0u8; 32];
        root_entropy.copy_from_slice(request.get_entropy());

        // Use root entropy to construct AccountKey.
        let root_id = RootIdentity {
            root_entropy,
            fog_url: None,
        };

        // TODO: change to production AccountKey derivation
        let account_key = AccountKey::from(&root_id);

        // Return response.
        let mut response = mobilecoind_api::GetAccountKeyResponse::new();
        response.set_account_key((&account_key).into());
        Ok(response)
    }

    fn get_public_address_impl(
        &mut self,
        request: mobilecoind_api::GetPublicAddressRequest,
    ) -> Result<mobilecoind_api::GetPublicAddressResponse, RpcStatus> {
        // Get MonitorId from from the GRPC request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

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
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("subaddress_index".to_string()),
            ));
        }

        // Get the subaddress.
        let subaddress = data.account_key.subaddress(request.subaddress_index);

        // Return response.
        let mut response = mobilecoind_api::GetPublicAddressResponse::new();
        response.set_public_address((&subaddress).into());
        Ok(response)
    }

    fn read_request_code_impl(
        &mut self,
        request: mobilecoind_api::ReadRequestCodeRequest,
    ) -> Result<mobilecoind_api::ReadRequestCodeResponse, RpcStatus> {
        let request_payload = RequestPayload::decode(request.get_b58_code())
            .map_err(|err| rpc_internal_error("RequestPayload.decode", err, &self.logger))?;

        let mut response = mobilecoind_api::ReadRequestCodeResponse::new();
        response.set_receiver(mobilecoind_api::PublicAddress::from(&PublicAddress::from(
            &request_payload,
        )));
        response.set_value(request_payload.value);
        response.set_memo(request_payload.memo);
        Ok(response)
    }

    fn get_request_code_impl(
        &mut self,
        request: mobilecoind_api::GetRequestCodeRequest,
    ) -> Result<mobilecoind_api::GetRequestCodeResponse, RpcStatus> {
        let receiver = PublicAddress::try_from(request.get_receiver())
            .map_err(|err| rpc_internal_error("PublicAddress.try_from", err, &self.logger))?;

        let view_key = receiver.view_public_key().to_bytes();
        let spend_key = receiver.spend_public_key().to_bytes();
        let fog_url = receiver.fog_url().unwrap_or("");

        let payload = RequestPayload::new_v3(
            &view_key,
            &spend_key,
            fog_url,
            request.get_value(),
            request.get_memo(),
        )
        .map_err(|err| rpc_internal_error("RequestPayload.new_v3", err, &self.logger))?;
        let b58_code = payload.encode();

        let mut response = mobilecoind_api::GetRequestCodeResponse::new();
        response.set_b58_code(b58_code);
        Ok(response)
    }

    fn read_transfer_code_impl(
        &mut self,
        request: mobilecoind_api::ReadTransferCodeRequest,
    ) -> Result<mobilecoind_api::ReadTransferCodeResponse, RpcStatus> {
        let transfer_payload = TransferPayload::decode(request.get_b58_code())
            .map_err(|err| rpc_internal_error("TransferPayload.decode", err, &self.logger))?;

        let tx_public_key = RistrettoPublic::try_from(&transfer_payload.utxo)
            .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let mut response = mobilecoind_api::ReadTransferCodeResponse::new();
        response.set_entropy(transfer_payload.entropy.to_vec());
        response.set_tx_public_key((&tx_public_key).into());
        response.set_memo(transfer_payload.memo);
        Ok(response)
    }

    fn get_transfer_code_impl(
        &mut self,
        request: mobilecoind_api::GetTransferCodeRequest,
    ) -> Result<mobilecoind_api::GetTransferCodeResponse, RpcStatus> {
        let mut entropy: [u8; 32] = [0; 32];
        if request.entropy.len() != entropy.len() {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("entropy".to_string()),
            ));
        }
        entropy.copy_from_slice(request.get_entropy());

        let tx_public_key = RistrettoPublic::try_from(request.get_tx_public_key())
            .map_err(|err| rpc_internal_error("RistrettoPublic.try_from", err, &self.logger))?;

        let payload =
            TransferPayload::new_v1(&entropy, &tx_public_key.to_bytes(), request.get_memo())
                .map_err(|err| rpc_internal_error("TransferPayload.new_v1", err, &self.logger))?;

        let b58_code = payload.encode();

        let mut response = mobilecoind_api::GetTransferCodeResponse::new();
        response.set_b58_code(b58_code);
        Ok(response)
    }

    fn generate_tx_impl(
        &mut self,
        request: mobilecoind_api::GenerateTxRequest,
    ) -> Result<mobilecoind_api::GenerateTxResponse, RpcStatus> {
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
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("change_subaddress".to_string()),
            ));
        }

        // Get the list of potential inputs passed to.
        let input_list: Vec<UnspentTxOut> = request
            .get_input_list()
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
                    return Err(RpcStatus::new(
                        RpcStatusCode::INVALID_ARGUMENT,
                        Some(format!("input_list.{}", i)),
                    ));
                }

                // Success.
                Ok(utxo)
            })
            .collect::<Result<Vec<UnspentTxOut>, RpcStatus>>()?;

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .get_outlay_list()
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                request.change_subaddress,
                &input_list,
                &outlays,
                request.fee,
                request.tombstone,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        // Success.
        let mut response = mobilecoind_api::GenerateTxResponse::new();
        response.set_tx_proposal((&tx_proposal).into());
        Ok(response)
    }

    fn generate_optimization_tx_impl(
        &mut self,
        request: mobilecoind_api::GenerateOptimizationTxRequest,
    ) -> Result<mobilecoind_api::GenerateOptimizationTxResponse, RpcStatus> {
        // Get monitor id from request.
        let monitor_id = MonitorId::try_from(&request.monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Generate optimization tx.
        let tx_proposal = self
            .transactions_manager
            .generate_optimization_tx(&monitor_id, request.subaddress)
            .map_err(|err| {
                rpc_internal_error(
                    "transactions_manager.generate_optimization_tx",
                    err,
                    &self.logger,
                )
            })?;

        // Success.
        let mut response = mobilecoind_api::GenerateOptimizationTxResponse::new();
        response.set_tx_proposal((&tx_proposal).into());
        Ok(response)
    }

    fn generate_transfer_code_tx_impl(
        &mut self,
        request: mobilecoind_api::GenerateTransferCodeTxRequest,
    ) -> Result<mobilecoind_api::GenerateTransferCodeTxResponse, RpcStatus> {
        // Generate entropy.
        let entropy_response = self.generate_entropy_impl(mobilecoind_api::Empty::new())?;
        let entropy = entropy_response.get_entropy().to_vec();

        let mut entropy_bytes = [0; 32];
        if entropy.len() != entropy_bytes.len() {
            return Err(RpcStatus::new(
                RpcStatusCode::INTERNAL,
                Some("entropy returned was not 32 bytes".to_owned()),
            ));
        }
        entropy_bytes.copy_from_slice(&entropy);

        // Generate a new account using this entropy.
        let mut account_key_request = mobilecoind_api::GetAccountKeyRequest::new();
        account_key_request.set_entropy(entropy.clone());

        let account_key_response = self.get_account_key_impl(account_key_request)?;
        let account_key = AccountKey::try_from(account_key_response.get_account_key())
            .map_err(|err| rpc_internal_error("account_key.try_from", err, &self.logger))?;

        // The outlay we are sending the money to.
        let outlay = Outlay {
            receiver: account_key.default_subaddress(),
            value: request.value,
        };

        // Generate transaction.
        let mut generate_tx_request = mobilecoind_api::GenerateTxRequest::new();
        generate_tx_request.set_sender_monitor_id(request.get_sender_monitor_id().to_vec());
        generate_tx_request.set_change_subaddress(request.change_subaddress);
        generate_tx_request.set_input_list(RepeatedField::from_vec(request.input_list.to_vec()));
        generate_tx_request.set_outlay_list(RepeatedField::from_vec(vec![(&outlay).into()]));
        generate_tx_request.set_fee(request.fee);
        generate_tx_request.set_tombstone(request.tombstone);

        let mut generate_tx_response = self.generate_tx_impl(generate_tx_request)?;
        let tx_proposal = generate_tx_response.take_tx_proposal();

        // Grab the public key of the relevant tx out.
        let proto_tx_public_key = {
            // We expect only a single outlay.
            if tx_proposal.get_outlay_index_to_tx_out_index().len() != 1 {
                return Err(RpcStatus::new(
                    RpcStatusCode::INTERNAL,
                    Some(format!(
                        "outlay_index_to_tx_out_index contains {} elements, was expecting 1",
                        tx_proposal.get_outlay_index_to_tx_out_index().len()
                    )),
                ));
            }

            // Get the TxOut index of our single outlay.
            let tx_out_index = tx_proposal
                .get_outlay_index_to_tx_out_index()
                .get(&0)
                .ok_or_else(|| {
                    RpcStatus::new(
                        RpcStatusCode::INTERNAL,
                        Some("outlay_index_to_tx_out_index doesn't contain index 0".to_owned()),
                    )
                })?;

            // Get the TxOut
            let tx_out = tx_proposal
                .get_tx()
                .get_prefix()
                .get_outputs()
                .get(*tx_out_index as usize)
                .ok_or_else(|| {
                    RpcStatus::new(
                        RpcStatusCode::INTERNAL,
                        Some(format!("tx out index {} not found", tx_out_index)),
                    )
                })?;

            // Get the public key
            tx_out.get_public_key().clone()
        };

        let tx_public_key = RistrettoPublic::try_from(&proto_tx_public_key)
            .map_err(|err| rpc_internal_error("ristretto_public.try_from", err, &self.logger))?;

        // Generate b58 code.
        let transfer_payload = TransferPayload::new_v1(
            &entropy_bytes,
            &tx_public_key.to_bytes(),
            request.get_memo(),
        )
        .map_err(|err| rpc_internal_error("transfer_payload.new_v1", err, &self.logger))?;
        let b58_code = transfer_payload.encode();

        // Construct response.
        let mut response = mobilecoind_api::GenerateTransferCodeTxResponse::new();
        response.set_tx_proposal(tx_proposal);
        response.set_entropy(entropy);
        response.set_tx_public_key(proto_tx_public_key);
        response.set_memo(request.get_memo().to_owned());
        response.set_b58_code(b58_code);
        Ok(response)
    }

    fn submit_tx_impl(
        &mut self,
        request: mobilecoind_api::SubmitTxRequest,
    ) -> Result<mobilecoind_api::SubmitTxResponse, RpcStatus> {
        // Get TxProposal from request.
        let tx_proposal = TxProposal::try_from(request.get_tx_proposal())
            .map_err(|err| rpc_internal_error("tx_proposal.try_from", err, &self.logger))?;

        // Submit to network.
        let block_height = self
            .transactions_manager
            .submit_tx_proposal(&tx_proposal)
            .map_err(|err| {
                rpc_internal_error("transactions_manager.submit_tx_proposal", err, &self.logger)
            })?;

        // Update the attempted spend block height in db. Note that we swallow the error here since
        // our transaction did get sent to the network, and its better to have the user attempt a
        // double spend by having stale UnspentTxOut data than having them not be aware that the
        // transaction was submitted.
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
        let mut sender_tx_receipt = mobilecoind_api::SenderTxReceipt::new();
        sender_tx_receipt.set_key_image_list(RepeatedField::from_vec(
            tx_proposal
                .utxos
                .iter()
                .map(|utxo| (&utxo.key_image).into())
                .collect(),
        ));
        sender_tx_receipt.set_tombstone(tx_proposal.tx.prefix.tombstone_block);

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
                        RpcStatus::new(
                            RpcStatusCode::INVALID_ARGUMENT,
                            Some("outlay_index_to_tx_out_index".to_string()),
                        )
                    })?;

                let tx_out = tx_proposal
                    .tx
                    .prefix
                    .outputs
                    .get(*tx_out_index)
                    .ok_or_else(|| {
                        RpcStatus::new(
                            RpcStatusCode::INVALID_ARGUMENT,
                            Some("outlay_index_to_tx_out_index".to_string()),
                        )
                    })?;

                let mut receiver_tx_receipt = mobilecoind_api::ReceiverTxReceipt::new();
                receiver_tx_receipt.set_receipient((&outlay.receiver).into());
                receiver_tx_receipt.set_tx_public_key(tx_out.public_key.into());
                receiver_tx_receipt.set_tx_out_hash(tx_out.hash().to_vec());
                receiver_tx_receipt.set_tombstone(tx_proposal.tx.prefix.tombstone_block);

                Ok(receiver_tx_receipt)
            })
            .collect::<Result<Vec<mobilecoind_api::ReceiverTxReceipt>, RpcStatus>>()?;

        // Return response.
        let mut response = mobilecoind_api::SubmitTxResponse::new();
        response.set_sender_tx_receipt(sender_tx_receipt);
        response.set_receiver_tx_receipt_list(RepeatedField::from_vec(receiver_tx_receipts));
        Ok(response)
    }

    fn get_ledger_info_impl(
        &mut self,
        _request: mobilecoind_api::Empty,
    ) -> Result<mobilecoind_api::GetLedgerInfoResponse, RpcStatus> {
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        let num_txos = self
            .ledger_db
            .num_txos()
            .map_err(|err| rpc_internal_error("ledger_db.num_txos", err, &self.logger))?;

        let mut response = mobilecoind_api::GetLedgerInfoResponse::new();
        response.set_block_count(num_blocks);
        response.set_txo_count(num_txos);
        Ok(response)
    }

    fn get_block_info_impl(
        &mut self,
        request: mobilecoind_api::GetBlockInfoRequest,
    ) -> Result<mobilecoind_api::GetBlockInfoResponse, RpcStatus> {
        // Get transactions for block and count number of Txos.
        let txs = self
            .ledger_db
            .get_transactions_by_block(request.block)
            .map_err(|err| {
                rpc_internal_error("ledger_db.get_transactions_by_block", err, &self.logger)
            })?;

        let num_tx_outs = txs.iter().flat_map(|tx| tx.outputs.iter()).count();

        // Get key images and count them.
        let key_images = self
            .ledger_db
            .get_key_images_by_block(request.block)
            .map_err(|err| {
                rpc_internal_error("ledger_db.get_key_images_by_block", err, &self.logger)
            })?;

        let num_key_images = key_images.len();

        // Return response.
        let mut response = mobilecoind_api::GetBlockInfoResponse::new();
        response.set_key_image_count(num_key_images as u64);
        response.set_txo_count(num_tx_outs as u64);
        Ok(response)
    }

    fn get_tx_status_as_sender_impl(
        &mut self,
        request: mobilecoind_api::GetTxStatusAsSenderRequest,
    ) -> Result<mobilecoind_api::GetTxStatusAsSenderResponse, RpcStatus> {
        // Sanity-test the request.
        if request.get_receipt().get_key_image_list().is_empty() {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.key_image_list".to_string()),
            ));
        }

        if request.get_receipt().tombstone == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.tombstone".to_string()),
            ));
        }

        // Get list of key images from request.
        let key_images: Vec<KeyImage> = request
            .get_receipt()
            .get_key_image_list()
            .iter()
            .map(|key_image| {
                KeyImage::try_from(key_image)
                    .map_err(|err| rpc_internal_error("key_image.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<KeyImage>, RpcStatus>>()?;

        // Convert key images to a list of booleans indicating whether they were found in the
        // ledger or not.
        let key_image_found: Vec<bool> = key_images
            .iter()
            .map(|key_image| {
                self.ledger_db.contains_key_image(key_image).map_err(|err| {
                    rpc_internal_error("ledger_db.contains_key_image", err, &self.logger)
                })
            })
            .collect::<Result<Vec<bool>, RpcStatus>>()?;

        // If all key images are in ledger, the transaction was completed.
        if key_image_found
            .iter()
            .all(|key_image_found| *key_image_found)
        {
            let mut response = mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mobilecoind_api::TxStatus::Verified);
            return Ok(response);
        }

        // If only some key images found their way to the ledger, something is weird.
        if key_image_found
            .iter()
            .any(|key_image_found| *key_image_found)
        {
            let mut response = mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mobilecoind_api::TxStatus::Unknown);
            return Ok(response);
        }

        // Check if the tombstone block was exceeded.
        let num_blocks = self
            .ledger_db
            .num_blocks()
            .map_err(|err| rpc_internal_error("ledger_db.num_blocks", err, &self.logger))?;

        if num_blocks >= request.get_receipt().tombstone {
            let mut response = mobilecoind_api::GetTxStatusAsSenderResponse::new();
            response.set_status(mobilecoind_api::TxStatus::TombstoneBlockExceeded);
            return Ok(response);
        }

        // No key images in ledger, tombstone block not yet exceeded.
        let mut response = mobilecoind_api::GetTxStatusAsSenderResponse::new();
        response.set_status(mobilecoind_api::TxStatus::Unknown);
        Ok(response)
    }

    fn get_tx_status_as_receiver_impl(
        &mut self,
        request: mobilecoind_api::GetTxStatusAsReceiverRequest,
    ) -> Result<mobilecoind_api::GetTxStatusAsReceiverResponse, RpcStatus> {
        // Sanity-test the request.
        if request.get_receipt().get_tx_out_hash().len() != 32 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.tx_out_hash".to_string()),
            ));
        }

        if request.get_receipt().tombstone == 0 {
            return Err(RpcStatus::new(
                RpcStatusCode::INVALID_ARGUMENT,
                Some("receipt.tombstone".to_string()),
            ));
        }
        // Check if the hash landed in the ledger.
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&request.get_receipt().tx_out_hash);

        match self.ledger_db.get_tx_out_index_by_hash(&hash_bytes) {
            Ok(_) => {
                // The hash found its way into the ledger, so the transaction succeeded.
                let mut response = mobilecoind_api::GetTxStatusAsReceiverResponse::new();
                response.set_status(mobilecoind_api::TxStatus::Verified);
                return Ok(response);
            }
            Err(ledger_db::Error::NotFound) => {}
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

        if num_blocks >= request.get_receipt().tombstone {
            let mut response = mobilecoind_api::GetTxStatusAsReceiverResponse::new();
            response.set_status(mobilecoind_api::TxStatus::TombstoneBlockExceeded);
            return Ok(response);
        }

        // Tx out not in ledger, tombstone block not yet exceeded.
        let mut response = mobilecoind_api::GetTxStatusAsReceiverResponse::new();
        response.set_status(mobilecoind_api::TxStatus::Unknown);
        Ok(response)
    }

    fn get_balance_impl(
        &mut self,
        request: mobilecoind_api::GetBalanceRequest,
    ) -> Result<mobilecoind_api::GetBalanceResponse, RpcStatus> {
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
        let balance = utxos.iter().map(|utxo| utxo.value).sum::<u64>();

        // Return response.
        let mut response = mobilecoind_api::GetBalanceResponse::new();
        response.set_balance(balance);
        Ok(response)
    }

    fn send_payment_impl(
        &mut self,
        request: mobilecoind_api::SendPaymentRequest,
    ) -> Result<mobilecoind_api::SendPaymentResponse, RpcStatus> {
        // Get sender monitor id from request.
        let sender_monitor_id = MonitorId::try_from(&request.sender_monitor_id)
            .map_err(|err| rpc_internal_error("monitor_id.try_from.bytes", err, &self.logger))?;

        // Get all utxos for this monitor id.
        let utxos = self
            .mobilecoind_db
            .get_utxos_for_subaddress(&sender_monitor_id, request.sender_subaddress)
            .map_err(|err| {
                rpc_internal_error("mobilecoind_db.get_utxos_for_subaddress", err, &self.logger)
            })?;

        // Get the list of outlays.
        let outlays: Vec<Outlay> = request
            .get_outlay_list()
            .iter()
            .map(|outlay_proto| {
                Outlay::try_from(outlay_proto)
                    .map_err(|err| rpc_internal_error("outlay.try_from", err, &self.logger))
            })
            .collect::<Result<Vec<Outlay>, RpcStatus>>()?;

        // Attempt to construct a transaction.
        let tx_proposal = self
            .transactions_manager
            .build_transaction(
                &sender_monitor_id,
                request.sender_subaddress,
                &utxos,
                &outlays,
                request.fee,
                request.tombstone,
            )
            .map_err(|err| {
                rpc_internal_error("transactions_manager.build_transaction", err, &self.logger)
            })?;

        let proto_tx_proposal = mobilecoind_api::TxProposal::from(&tx_proposal);

        // Submit transaction.
        let mut submit_tx_request = mobilecoind_api::SubmitTxRequest::new();
        submit_tx_request.set_tx_proposal(proto_tx_proposal.clone());
        let mut submit_tx_response = self.submit_tx_impl(submit_tx_request)?;

        // Return response.
        let mut response = mobilecoind_api::SendPaymentResponse::new();
        response.set_sender_tx_receipt(submit_tx_response.take_sender_tx_receipt());
        response.set_receiver_tx_receipt_list(submit_tx_response.take_receiver_tx_receipt_list());
        response.set_tx_proposal(proto_tx_proposal);
        Ok(response)
    }
}

macro_rules! build_api {
    ($( $service_function_name:ident $service_request_type:ident $service_response_type:ident $service_function_impl:ident ),+)
    =>
    (
        impl<T: UserTxConnection + 'static> MobilecoindApi for ServiceApi<T> {
            $(
                fn $service_function_name(
                    &mut self,
                    ctx: RpcContext,
                    request: mobilecoind_api::$service_request_type,
                    sink: UnarySink<mobilecoind_api::$service_response_type>,
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
    add_monitor AddMonitorRequest AddMonitorResponse add_monitor_impl,
    remove_monitor RemoveMonitorRequest Empty remove_monitor_impl,
    get_monitor_list Empty GetMonitorListResponse get_monitor_list_impl,
    get_monitor_status GetMonitorStatusRequest GetMonitorStatusResponse get_monitor_status_impl,
    get_unspent_tx_out_list GetUnspentTxOutListRequest GetUnspentTxOutListResponse get_unspent_tx_out_list_impl,
    generate_entropy Empty GenerateEntropyResponse generate_entropy_impl,
    get_account_key GetAccountKeyRequest GetAccountKeyResponse get_account_key_impl,
    get_public_address GetPublicAddressRequest GetPublicAddressResponse get_public_address_impl,
    read_request_code ReadRequestCodeRequest ReadRequestCodeResponse read_request_code_impl,
    get_request_code GetRequestCodeRequest GetRequestCodeResponse get_request_code_impl,
    read_transfer_code ReadTransferCodeRequest ReadTransferCodeResponse read_transfer_code_impl,
    get_transfer_code GetTransferCodeRequest GetTransferCodeResponse get_transfer_code_impl,
    generate_tx GenerateTxRequest GenerateTxResponse generate_tx_impl,
    generate_optimization_tx GenerateOptimizationTxRequest GenerateOptimizationTxResponse generate_optimization_tx_impl,
    generate_transfer_code_tx GenerateTransferCodeTxRequest GenerateTransferCodeTxResponse generate_transfer_code_tx_impl,
    submit_tx SubmitTxRequest SubmitTxResponse submit_tx_impl,
    get_ledger_info Empty GetLedgerInfoResponse get_ledger_info_impl,
    get_block_info GetBlockInfoRequest GetBlockInfoResponse get_block_info_impl,
    get_tx_status_as_sender GetTxStatusAsSenderRequest GetTxStatusAsSenderResponse get_tx_status_as_sender_impl,
    get_tx_status_as_receiver GetTxStatusAsReceiverRequest GetTxStatusAsReceiverResponse get_tx_status_as_receiver_impl,
    get_balance GetBalanceRequest GetBalanceResponse get_balance_impl,
    send_payment SendPaymentRequest SendPaymentResponse send_payment_impl
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        payments::DEFAULT_NEW_TX_BLOCK_ATTEMPTS,
        test_utils::{
            self, add_block_to_ledger_db, get_testing_environment, wait_for_monitors,
            PER_RECIPIENT_AMOUNT,
        },
        utxo_store::UnspentTxOut,
    };
    use common::{logger::test_with_logger, HashSet};
    use keys::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};
    use std::{convert::TryFrom, iter::FromIterator};
    use transaction::{
        account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX},
        constants::{BASE_FEE, MAX_INPUTS, RING_SIZE},
        get_tx_out_shared_secret,
        onetime_keys::{compute_key_image, recover_onetime_private_key},
        tx::{Tx, TxOut},
        Block, BlockIndex, BLOCK_VERSION,
    };

    #[test_with_logger]
    fn test_add_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([20u8; 32]);

        // Three random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Create request for adding a new monitor.
        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            DEFAULT_SUBADDRESS_INDEX, // first_subaddress
            1,                        // num_subaddresses
            0,                        // first_block
        )
        .expect("failed to create data");

        let mut request = mobilecoind_api::AddMonitorRequest::new();
        request.set_account_key(mobilecoind_api::AccountKey::from(&data.account_key));
        request.set_first_subaddress(data.first_subaddress);
        request.set_num_subaddresses(data.num_subaddresses);
        request.set_first_block(data.first_block);

        // Send request.
        let response = client.add_monitor(&request).expect("failed to add monitor");

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Compare the MonitorId we got back to the value we expected.
        let monitor_id = MonitorId::try_from(&response.monitor_id)
            .expect("failed to convert response to MonitorId");
        let expected_monitor_id = MonitorId::from(&data);

        assert_eq!(expected_monitor_id, monitor_id);
    }

    #[test_with_logger]
    fn test_remove_monitor_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([22u8; 32]);

        // 10 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

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
                )
                .unwrap();
                mobilecoind_db.add_monitor(&data).unwrap()
            })
            .collect();

        let monitors_map = mobilecoind_db.get_monitor_map().unwrap();
        assert_eq!(monitors_to_add, monitors_map.len());

        // Remove all the monitors we added.
        for id in monitor_ids {
            let mut request = mobilecoind_api::RemoveMonitorRequest::new();
            request.set_monitor_id(id.to_vec());
            client
                .remove_monitor(&request)
                .expect("failed to remove monitor");
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
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        // Add some new monitors directly to the database.
        let monitors_to_add = 10;
        let monitor_ids: Vec<MonitorId> = (0..monitors_to_add)
            .map(|_i| {
                let data = MonitorData::new(
                    AccountKey::random(&mut rng),
                    DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                    1,                        // num_subaddresses
                    0,                        // first_block
                )
                .unwrap();
                let id = mobilecoind_db.add_monitor(&data).unwrap();
                log::debug!(logger, "adding monitor {}", id,);
                id
            })
            .collect();

        // Ask the api for a list of all monitors.
        let response = client
            .get_monitor_list(&mobilecoind_api::Empty::new())
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
            get_testing_environment(10, &vec![], &vec![], logger.clone(), &mut rng);

        let data = MonitorData::new(
            AccountKey::random(&mut rng),
            10, // first_subaddress
            20, // num_subaddresses
            30, // first_block
        )
        .unwrap();

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query monitor status.
        let mut request = mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(id.to_vec());

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

        // Calling get_monitor_status for nonexistent or invalid monitor_id should return an error.
        mobilecoind_db.remove_monitor(&id).unwrap();

        let mut request = mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(id.to_vec());
        assert!(client.get_monitor_status(&request).is_err());

        let request = mobilecoind_api::GetMonitorStatusRequest::new();
        assert!(client.get_monitor_status(&request).is_err());

        let mut request = mobilecoind_api::GetMonitorStatusRequest::new();
        request.set_monitor_id(vec![3; 3]);
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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![account_key.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Query for unspent tx outs for a subaddress that did not receive any tx outs.
        let mut request = mobilecoind_api::GetUnspentTxOutListRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1);

        let response = client
            .get_unspent_tx_out_list(&request)
            .expect("failed to get unspent tx out list");

        assert_eq!(response.output_list.to_vec(), vec![]);

        // Query wit hthe correct subaddress index.
        let mut request = mobilecoind_api::GetUnspentTxOutListRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);

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

        // Verify the data we got matches what we expected. This assumes knowledge about how the
        // test ledger is constructed by the test utils.
        let num_blocks = ledger_db.num_blocks().unwrap();
        let account_tx_outs: Vec<TxOut> = (0..num_blocks)
            .map(|idx| {
                let redacted_txs = ledger_db.get_transactions_by_block(idx as u64).unwrap();
                // We grab the 4th tx out in each block since the test ledger had 3 random
                // recipients, followed by our known recipient.
                // See the call to `get_testing_environment` at the beginning of the test.
                redacted_txs[0].outputs[3].clone()
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
                    &account_key.subaddress_spend_key(0),
                );
                let key_image = compute_key_image(&onetime_private_key);

                // Craft the expected UnspentTxOut
                UnspentTxOut {
                    tx_out: tx_out.clone(),
                    subaddress_index: 0,
                    key_image,
                    value: test_utils::PER_RECIPIENT_AMOUNT,
                    attempted_spend_height: 0,
                    attempted_spend_tombstone: 0,
                }
            })
            .collect();

        // Compare
        assert_eq!(utxos.len(), num_blocks as usize);
        assert_eq!(
            HashSet::from_iter(utxos),
            HashSet::from_iter(expected_utxos)
        );
    }

    #[test_with_logger]
    fn test_generate_root_entropy_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // call get entropy
        let response = client
            .generate_entropy(&mobilecoind_api::Empty::default())
            .unwrap();
        let entropy = response.get_entropy().to_vec();
        assert_eq!(entropy.len(), 32);
        assert_ne!(entropy, vec![0; 32]);
    }

    #[test_with_logger]
    fn test_get_account_key_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // call get account key
        let root_entropy = [123u8; 32];
        let mut request = mobilecoind_api::GetAccountKeyRequest::new();
        request.set_entropy(root_entropy.to_vec());

        let response = client.get_account_key(&request).unwrap();

        // TODO: change to production AccountKey derivation
        let root_id = RootIdentity {
            root_entropy,
            fog_url: None,
        };
        assert_eq!(
            AccountKey::from(&root_id),
            AccountKey::try_from(response.get_account_key()).unwrap(),
        );

        // Calling with no root entropy or invalid root entropy should error.
        let request = mobilecoind_api::GetAccountKeyRequest::new();
        assert!(client.get_account_key(&request).is_err());

        let root_entropy = [123u8; 31];
        let mut request = mobilecoind_api::GetAccountKeyRequest::new();
        request.set_entropy(root_entropy.to_vec());
        assert!(client.get_account_key(&request).is_err());
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
        )
        .unwrap();

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Call get public address.
        let mut request = mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(10);
        let response = client.get_public_address(&request).unwrap();

        assert_eq!(
            PublicAddress::try_from(response.get_public_address()).unwrap(),
            account_key.subaddress(10)
        );

        // Subaddress that is out of index or an invalid monitor id should error.
        let request = mobilecoind_api::GetPublicAddressRequest::new();
        assert!(client.get_public_address(&request).is_err());

        let mut request = mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(vec![3; 3]);
        request.set_subaddress_index(10);
        assert!(client.get_public_address(&request).is_err());

        let mut request = mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);
        assert!(client.get_public_address(&request).is_err());

        let mut request = mobilecoind_api::GetPublicAddressRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1000);
        assert!(client.get_public_address(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_ledger_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Call get ledger info.
        let response = client
            .get_ledger_info(&mobilecoind_api::Empty::new())
            .unwrap();
        assert_eq!(response.block_count, ledger_db.num_blocks().unwrap());
        assert_eq!(response.txo_count, ledger_db.num_txos().unwrap());
    }

    #[test_with_logger]
    fn test_get_block_info_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Call get block info for a valid block.
        let mut request = mobilecoind_api::GetBlockInfoRequest::new();
        request.set_block(0);

        let response = client.get_block_info(&request).unwrap();
        assert_eq!(response.key_image_count, 0); // test code does not generate any key images
        assert_eq!(response.txo_count, 3); // 3 recipients = 3 tx outs

        // Call with an invalid block number.
        let mut request = mobilecoind_api::GetBlockInfoRequest::new();
        request.set_block(ledger_db.num_blocks().unwrap());

        assert!(client.get_block_info(&request).is_err());
    }

    #[test_with_logger]
    fn test_get_tx_status_as_sender_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Insert a block with some key images in it.
        let recipient = AccountKey::random(&mut rng).default_subaddress();
        add_block_to_ledger_db(
            &mut ledger_db,
            &[recipient],
            &[KeyImage::from(1), KeyImage::from(2), KeyImage::from(3)],
            &mut rng,
        );

        // A receipt with all key images in ledger is verified.
        {
            let mut receipt = mobilecoind_api::SenderTxReceipt::new();
            receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
                (&KeyImage::from(3)).into(),
            ]));
            receipt.set_tombstone(1);

            let mut request = mobilecoind_api::GetTxStatusAsSenderRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.get_status(), mobilecoind_api::TxStatus::Verified);
        }

        // A receipt with an extra key image should be Unknown.
        {
            let mut receipt = mobilecoind_api::SenderTxReceipt::new();
            receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(1)).into(),
                (&KeyImage::from(2)).into(),
                (&KeyImage::from(3)).into(),
                (&KeyImage::from(4)).into(),
            ]));
            receipt.set_tombstone(1);

            let mut request = mobilecoind_api::GetTxStatusAsSenderRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.get_status(), mobilecoind_api::TxStatus::Unknown);
        }

        // A receipt with key images that are not in the ledger is pending (unknown) if its tombstone block
        // has not been exceeded.
        {
            let mut receipt = mobilecoind_api::SenderTxReceipt::new();
            receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(4)).into(),
                (&KeyImage::from(5)).into(),
            ]));
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64 + 1);

            let mut request = mobilecoind_api::GetTxStatusAsSenderRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(response.get_status(), mobilecoind_api::TxStatus::Unknown);
        }

        // A receipt with key images that are not in the ledger having its tombstone block exceeded.
        {
            let mut receipt = mobilecoind_api::SenderTxReceipt::new();
            receipt.set_key_image_list(RepeatedField::from_vec(vec![
                (&KeyImage::from(4)).into(),
                (&KeyImage::from(5)).into(),
            ]));
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64);

            let mut request = mobilecoind_api::GetTxStatusAsSenderRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_sender(&request).unwrap();

            assert_eq!(
                response.get_status(),
                mobilecoind_api::TxStatus::TombstoneBlockExceeded
            );
        }
    }

    #[test_with_logger]
    fn test_get_tx_status_as_receiver_impl(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // A call with an invalid hash should fail
        {
            let mut receipt = mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tombstone(1);

            let mut request = mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            assert!(client.get_tx_status_as_receiver(&request).is_err());
        }

        // A call with a hash thats in the ledger should return Verified
        {
            let tx_out = ledger_db.get_tx_out_by_index(1).unwrap();
            let hash = tx_out.hash();

            let mut receipt = mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(1);

            let mut request = mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.get_status(), mobilecoind_api::TxStatus::Verified);
        }

        // A call with a hash thats is not in the ledger and hasn't exceeded tombstone block should
        // return Unknown
        {
            let hash = [0; 32];

            let mut receipt = mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64 + 1);

            let mut request = mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(response.get_status(), mobilecoind_api::TxStatus::Unknown);
        }

        // A call with a hash thats is not in the ledger and has exceeded tombstone block should
        // return TombstoneBlockExceeded
        {
            let hash = [0; 32];

            let mut receipt = mobilecoind_api::ReceiverTxReceipt::new();
            receipt.set_tx_out_hash(hash.to_vec());
            receipt.set_tombstone(ledger_db.num_blocks().unwrap() as u64);

            let mut request = mobilecoind_api::GetTxStatusAsReceiverRequest::new();
            request.set_receipt(receipt);

            let response = client.get_tx_status_as_receiver(&request).unwrap();
            assert_eq!(
                response.get_status(),
                mobilecoind_api::TxStatus::TombstoneBlockExceeded
            );
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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
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
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call generate tx.
        let mut request = mobilecoind_api::GenerateTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_outlay_list(RepeatedField::from_vec(
            outlays.iter().map(mobilecoind_api::Outlay::from).collect(),
        ));

        // Test the happy flow.
        {
            let response = client.generate_tx(&request).unwrap();

            // Sanity test the response.
            let tx_proposal = response.get_tx_proposal();

            let expected_num_inputs: u64 = (outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                / test_utils::PER_RECIPIENT_AMOUNT)
                + 1;
            assert_eq!(
                tx_proposal.get_input_list().len(),
                expected_num_inputs as usize
            );
            assert_eq!(
                tx_proposal.get_tx().get_prefix().get_inputs().len(),
                expected_num_inputs as usize
            );
            assert_eq!(tx_proposal.get_outlay_list(), request.get_outlay_list());
            assert_eq!(
                tx_proposal.get_tx().get_prefix().get_outputs().len(),
                outlays.len() + 1
            ); // Extra output for change.

            // Sanity test output amounts
            let tx = Tx::try_from(tx_proposal.get_tx()).unwrap();

            let change = test_utils::PER_RECIPIENT_AMOUNT
                - outlays.iter().map(|outlay| outlay.value).sum::<u64>()
                - BASE_FEE;

            for (account_key, tx_out, expected_amount) in &[
                (&receiver1, &tx.prefix.outputs[0], outlays[0].value),
                (&receiver2, &tx.prefix.outputs[1], outlays[1].value),
                (&sender, &tx.prefix.outputs[2], change),
            ] {
                let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
                let shared_secret =
                    get_tx_out_shared_secret(account_key.view_private_key(), &tx_public_key);
                let (value, _blinding) = tx_out.amount.get_value(&shared_secret).unwrap();
                assert_eq!(value, *expected_amount);
            }

            // Santity test fee
            assert_eq!(tx_proposal.get_fee(), BASE_FEE);
            assert_eq!(tx_proposal.get_tx().get_prefix().fee, BASE_FEE);

            // Sanity test tombstone block
            let num_blocks = ledger_db.num_blocks().unwrap();
            assert_eq!(
                tx_proposal.get_tx().get_prefix().tombstone_block,
                num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
            );
        }

        // Invalid input scenarios should result in an error.
        {
            // No monitor id
            let mut request = request.clone();
            request.set_sender_monitor_id(vec![]);
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Unrecognized monitor id
            let sender = AccountKey::random(&mut rng);
            let data = MonitorData::new(
                sender.clone(),
                0,  // first_subaddress
                20, // num_subaddresses
                0,  // first_block
            )
            .unwrap();

            let mut request = request.clone();
            request.set_sender_monitor_id(MonitorId::from(&data).to_vec());
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Subaddress index out of range
            let mut request = request.clone();
            request.set_change_subaddress(data.first_subaddress + data.num_subaddresses + 1);
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Junk input
            let mut request = request.clone();
            request
                .mut_input_list()
                .push(mobilecoind_api::UnspentTxOut::default());
            assert!(client.generate_tx(&request).is_err());
        }

        {
            // Attempt to spend more than we have
            let num_blocks = ledger_db.num_blocks().unwrap();
            let mut request = request.clone();
            request.set_outlay_list(RepeatedField::from_vec(vec![
                mobilecoind_api::Outlay::from(&Outlay {
                    receiver: receiver1.default_subaddress(),
                    value: test_utils::PER_RECIPIENT_AMOUNT * num_blocks,
                }),
            ]));
            assert!(client.generate_tx(&request).is_err());
        }
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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
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
        let mut request = mobilecoind_api::GenerateTransferCodeTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_value(1337);

        let response = client.generate_transfer_code_tx(&request).unwrap();

        // Test that the generated transaction can be picked up by mobilecoind.
        {
            // Get the transaction, and redact it so that we could append it to the ledger.
            let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();
            let redacted_transactions = vec![tx_proposal.tx.redact()];

            // Append to ledger.
            let num_blocks = ledger_db.num_blocks().unwrap();
            let parent = ledger_db.get_block(num_blocks - 1).unwrap();
            let new_block = Block::new(
                BLOCK_VERSION,
                &parent.id,
                num_blocks as BlockIndex,
                parent.cumulative_txo_count + redacted_transactions.len() as u64,
                &Default::default(),
                &redacted_transactions,
            );
            ledger_db
                .append_block(&new_block, &redacted_transactions, None)
                .unwrap();

            // Add a monitor based on the entropy we received.
            let mut root_entropy = [0; 32];
            root_entropy.copy_from_slice(response.get_entropy());
            let root_id = RootIdentity {
                root_entropy,
                fog_url: None,
            };

            // TODO: change to production AccountKey derivation
            let account_key = AccountKey::from(&root_id);
            let monitor_data = MonitorData::new(
                account_key,
                DEFAULT_SUBADDRESS_INDEX, // first_subaddress
                1,                        // num_subaddresses
                0,                        // first_block
            )
            .unwrap();

            let monitor_id = mobilecoind_db.add_monitor(&monitor_data).unwrap();

            // Wait for sync to complete.
            wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

            // Get utxos for the new account and verify we only have the one utxo we are looking forc.
            let utxos = mobilecoind_db
                .get_utxos_for_subaddress(&monitor_id, 0)
                .unwrap();
            assert_eq!(utxos.len(), 1);

            let utxo = &utxos[0];

            assert_eq!(utxo.value, 1337);
            assert_eq!(
                utxo.tx_out.public_key,
                RistrettoPublic::try_from(response.get_tx_public_key())
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
            sender.clone(),
            0,  // first_subaddress
            20, // num_subaddresses
            0,  // first_block
        )
        .unwrap();

        // 1 known recipient, and a bunch of random recipients and no monitors.
        // The random recipients are needed for mixins.
        let num_random_recipients = MAX_INPUTS as u32 * RING_SIZE as u32
            / test_utils::GET_TESTING_ENVIRONMENT_NUM_BLOCKS as u32;
        let (mut ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                num_random_recipients as u32,
                &vec![sender_default_subaddress.clone()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Add a bunch of blocks/utxos for our recipient.
        for _ in 0..MAX_INPUTS {
            let _ = add_block_to_ledger_db(
                &mut ledger_db,
                &[sender_default_subaddress.clone()],
                &[],
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
        let mut request = mobilecoind_api::GenerateOptimizationTxRequest::new();
        request.set_monitor_id(monitor_id.to_vec());
        request.set_subaddress(0);

        let response = client.generate_optimization_tx(&request).unwrap();

        // Sanity test the response.
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();

        let expected_num_inputs: usize = MAX_INPUTS as usize;
        assert_eq!(tx_proposal.utxos.len(), expected_num_inputs);
        assert_eq!(tx_proposal.tx.prefix.inputs.len(), expected_num_inputs);

        assert_eq!(tx_proposal.outlays.len(), 1);
        assert_eq!(
            tx_proposal.outlays[0].receiver,
            data.account_key.subaddress(0)
        );
        assert_eq!(
            tx_proposal.outlays[0].value,
            // Each UTXO we have has PER_RECIPIENT_AMOUNT coins. We will be merging MAX_INPUTS of those
            // into a single output, minus the fee.
            (PER_RECIPIENT_AMOUNT * MAX_INPUTS as u64) - BASE_FEE,
        );

        assert_eq!(tx_proposal.outlay_index_to_tx_out_index.len(), 1);
        assert_eq!(tx_proposal.outlay_index_to_tx_out_index[&0], 0);

        assert_eq!(tx_proposal.tx.prefix.outputs.len(), 1);
        let tx_out = &tx_proposal.tx.prefix.outputs[0];
        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();
        let shared_secret =
            get_tx_out_shared_secret(data.account_key.view_private_key(), &tx_public_key);
        let (value, _blinding) = tx_out.amount.get_value(&shared_secret).unwrap();
        assert_eq!(value, tx_proposal.outlays[0].value);

        // Santity test fee
        assert_eq!(tx_proposal.fee(), BASE_FEE);
        assert_eq!(tx_proposal.tx.prefix.fee, BASE_FEE);

        // Sanity test tombstone block
        let num_blocks = ledger_db.num_blocks().unwrap();
        assert_eq!(
            tx_proposal.tx.prefix.tombstone_block,
            num_blocks + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
        );
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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
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
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call generate tx.
        let mut request = mobilecoind_api::GenerateTxRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_change_subaddress(0);
        request.set_input_list(RepeatedField::from_vec(
            utxos
                .iter()
                .map(mobilecoind_api::UnspentTxOut::from)
                .collect(),
        ));
        request.set_outlay_list(RepeatedField::from_vec(
            outlays.iter().map(mobilecoind_api::Outlay::from).collect(),
        ));

        // Get our propsal which we'll use for the test.
        let response = client.generate_tx(&request).unwrap();
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();
        let tx = tx_proposal.tx.clone();

        // Test the happy flow.
        {
            let mut request = mobilecoind_api::SubmitTxRequest::new();
            request.set_tx_proposal(mobilecoind_api::TxProposal::from(&tx_proposal));

            let response = client.submit_tx(&request).unwrap();

            // Get the submitted transaction - it was submitted to one of our mock peers, but we
            // don't know to which. We enforce the invariant that only one transaction should've been
            // submitted.
            let mut opt_submitted_tx: Option<Tx> = None;
            for mock_peer in server_conn_manager.conns() {
                let inner = mock_peer.read();
                match (inner.submitted_txs.len(), opt_submitted_tx.clone()) {
                    (0, _) => {
                        // Nothing submitted to the current peer.
                    }
                    (1, None) => {
                        // Found our tx.
                        opt_submitted_tx = Some(inner.submitted_txs[0].clone())
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
                .get_sender_tx_receipt()
                .get_key_image_list()
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
                response.get_sender_tx_receipt().tombstone,
                tx.prefix.tombstone_block
            );

            // Sanity the receiver receipts.
            assert_eq!(response.get_receiver_tx_receipt_list().len(), outlays.len());
            for (outlay, receipt) in outlays
                .iter()
                .zip(response.get_receiver_tx_receipt_list().iter())
            {
                assert_eq!(
                    outlay.receiver,
                    PublicAddress::try_from(receipt.get_receipient()).unwrap()
                );

                assert_eq!(receipt.tombstone, tx.prefix.tombstone_block);
            }

            assert_eq!(
                response.get_receiver_tx_receipt_list().len() + 1, // There's a change output that is not part of the receipts
                tx.prefix.outputs.len()
            );
            for (tx_out, receipt) in tx
                .prefix
                .outputs
                .iter()
                .zip(response.get_receiver_tx_receipt_list().iter())
            {
                assert_eq!(tx_out.hash(), receipt.get_tx_out_hash(),);

                assert_eq!(
                    tx_out.public_key.as_bytes(),
                    receipt.get_tx_public_key().get_data(),
                );
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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(
                3,
                &vec![account_key.default_subaddress()],
                &vec![],
                logger.clone(),
                &mut rng,
            );

        // Insert into database.
        let id = mobilecoind_db.add_monitor(&data).unwrap();

        // Allow the new monitor to process the ledger.
        wait_for_monitors(&mobilecoind_db, &ledger_db, &logger);

        // Get balance for a monitor_id/subaddress index that has a balance.
        let mut request = mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(0);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(
            response.balance,
            test_utils::PER_RECIPIENT_AMOUNT * ledger_db.num_blocks().unwrap()
        );

        // Get balance for subaddress with no utxos should return 0.
        let mut request = mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id.to_vec());
        request.set_subaddress_index(1);

        let response = client.get_balance(&request).unwrap();
        assert_eq!(response.balance, 0);

        // Non-existent monitor id should return 0
        let mut id2 = id.clone().to_vec();
        id2[0] = !id2[0];

        let mut request = mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(id2);
        request.set_subaddress_index(0);

        assert_eq!(response.balance, 0);

        // Invalid monitor id should error
        let mut request = mobilecoind_api::GetBalanceRequest::new();
        request.set_monitor_id(vec![1; 2]);
        request.set_subaddress_index(0);

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
        )
        .unwrap();

        // 1 known recipient, 3 random recipients and no monitors.
        let (ledger_db, mobilecoind_db, client, _server, server_conn_manager) =
            get_testing_environment(
                3,
                &vec![sender.default_subaddress()],
                &vec![],
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
            },
            Outlay {
                value: 456,
                receiver: receiver2.default_subaddress(),
            },
        ];

        // Call send payment.
        let mut request = mobilecoind_api::SendPaymentRequest::new();
        request.set_sender_monitor_id(monitor_id.to_vec());
        request.set_sender_subaddress(0);
        request.set_outlay_list(RepeatedField::from_vec(
            outlays.iter().map(mobilecoind_api::Outlay::from).collect(),
        ));

        let response = client.send_payment(&request).unwrap();

        // Get the submitted transaction - it was submitted to one of our mock peers, but we
        // don't know to which. We enforce the invariant that only one transaction should've been
        // submitted.
        let mut opt_submitted_tx: Option<Tx> = None;
        for mock_peer in server_conn_manager.conns() {
            let inner = mock_peer.read();
            match (inner.submitted_txs.len(), opt_submitted_tx.clone()) {
                (0, _) => {
                    // Nothing submitted to the current peer.
                }
                (1, None) => {
                    // Found our tx.
                    opt_submitted_tx = Some(inner.submitted_txs[0].clone())
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
            Tx::try_from(response.get_tx_proposal().get_tx()).unwrap()
        );

        // Sanity test sender receipt
        let key_images: Vec<KeyImage> = response
            .get_sender_tx_receipt()
            .get_key_image_list()
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
            response.get_sender_tx_receipt().tombstone,
            submitted_tx.prefix.tombstone_block
        );

        // Sanity the receiver receipts.
        assert_eq!(response.get_receiver_tx_receipt_list().len(), outlays.len());
        for (outlay, receipt) in outlays
            .iter()
            .zip(response.get_receiver_tx_receipt_list().iter())
        {
            assert_eq!(
                outlay.receiver,
                PublicAddress::try_from(receipt.get_receipient()).unwrap()
            );

            assert_eq!(receipt.tombstone, submitted_tx.prefix.tombstone_block);
        }

        assert_eq!(
            response.get_receiver_tx_receipt_list().len() + 1, // There's a change output that is not part of the receipts
            submitted_tx.prefix.outputs.len()
        );
        for (tx_out, receipt) in submitted_tx
            .prefix
            .outputs
            .iter()
            .zip(response.get_receiver_tx_receipt_list().iter())
        {
            assert_eq!(tx_out.hash(), receipt.get_tx_out_hash(),);

            assert_eq!(
                tx_out.public_key.as_bytes(),
                receipt.get_tx_public_key().get_data(),
            );
        }

        // Check that attempted_spend_height got updated for the relevant utxos.
        let tx_proposal = TxProposal::try_from(response.get_tx_proposal()).unwrap();

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
    fn test_request_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Random receiver address.
        let receiver = AccountKey::random(&mut rng).default_subaddress();

        // Try with just a receiver
        {
            // Generate a request code
            let mut request = mobilecoind_api::GetRequestCodeRequest::new();
            request.set_receiver(mobilecoind_api::PublicAddress::from(&receiver));

            let response = client.get_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mobilecoind_api::ReadRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_owned());

            let response = client.read_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 0);
            assert_eq!(response.get_memo(), "");
        }
        // Try with receiver and value
        {
            // Generate a request code
            let mut request = mobilecoind_api::GetRequestCodeRequest::new();
            request.set_receiver(mobilecoind_api::PublicAddress::from(&receiver));
            request.set_value(1234567890);

            let response = client.get_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mobilecoind_api::ReadRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_owned());

            let response = client.read_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.get_memo(), "");
        }
        // Try with receiver, value and memo
        {
            // Generate a request code
            let mut request = mobilecoind_api::GetRequestCodeRequest::new();
            request.set_receiver(mobilecoind_api::PublicAddress::from(&receiver));
            request.set_value(1234567890);
            request.set_memo("hello there".to_owned());

            let response = client.get_request_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Attempt to decode it.
            let mut request = mobilecoind_api::ReadRequestCodeRequest::new();
            request.set_b58_code(b58_code.to_owned());

            let response = client.read_request_code(&request).unwrap();

            // Check that input equals output.
            assert_eq!(
                PublicAddress::try_from(response.get_receiver()).unwrap(),
                receiver
            );
            assert_eq!(response.value, 1234567890);
            assert_eq!(response.get_memo(), "hello there");
        }

        // Attempting to decode junk data should fail
        {
            let mut request = mobilecoind_api::ReadRequestCodeRequest::new();
            request.set_b58_code("junk".to_owned());

            assert!(client.read_request_code(&request).is_err());
        }
    }

    #[test_with_logger]
    fn test_transfer_code(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([23u8; 32]);

        // no known recipient, 3 random recipients and no monitors.
        let (_ledger_db, _mobilecoind_db, client, _server, _server_conn_manager) =
            get_testing_environment(3, &vec![], &vec![], logger.clone(), &mut rng);

        // Text public key
        let tx_public_key = RistrettoPublic::from_random(&mut rng);

        // An invalid request should fail.
        {
            let mut request = mobilecoind_api::GetTransferCodeRequest::new();
            request.set_entropy(vec![3; 8]);
            request.set_tx_public_key((&tx_public_key).into());
            request.set_memo("memo".to_owned());
            assert!(client.get_transfer_code(&request).is_err());

            let mut request = mobilecoind_api::GetTransferCodeRequest::new();
            request.set_memo("memo".to_owned());
            assert!(client.get_transfer_code(&request).is_err());
        }

        // A valid request should allow us to encode to b58 and back to the original data.
        {
            // Encode
            let mut request = mobilecoind_api::GetTransferCodeRequest::new();
            request.set_entropy(vec![3; 32]);
            request.set_tx_public_key((&tx_public_key).into());
            request.set_memo("test memo".to_owned());

            let response = client.get_transfer_code(&request).unwrap();
            let b58_code = response.get_b58_code();

            // Decode
            let mut request = mobilecoind_api::ReadTransferCodeRequest::new();
            request.set_b58_code(b58_code.to_owned());

            let response = client.read_transfer_code(&request).unwrap();

            // Compare
            assert_eq!(vec![3; 32], response.get_entropy());
            assert_eq!(
                tx_public_key,
                RistrettoPublic::try_from(response.get_tx_public_key()).unwrap()
            );
            assert_eq!(response.get_memo(), "test memo");
        }
    }
}
