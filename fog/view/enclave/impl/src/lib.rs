// Copyright (c) 2018-2022 The MobileCoin Foundation

//! View Enclave Implementation

#![no_std]

extern crate alloc;

mod e_tx_out_store;
use e_tx_out_store::{ETxOutStore, StorageDataSize, StorageMetaSize};

use aes_gcm::Aes256Gcm;
use alloc::vec::Vec;
use core::ops::DerefMut;
use mc_attest_ake::Ready;
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_common::logger::{log, Logger};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_fog_recovery_db_iface::FogUserEvent;
use mc_fog_types::{
    view::{QueryRequest, QueryResponse},
    ETxOutRecord,
};
use mc_fog_view_enclave_api::{
    Error, Result, UntrustedQueryResponse, ViewEnclaveApi, ViewEnclaveInitParams,
};
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};

pub struct ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// The encrypted storage
    e_tx_out_store: Mutex<Option<ETxOutStore<OSC>>>,

    /// The state associated to attestation and key exchange
    ake: AkeEnclaveState<NullIdentity>,

    /// Logger object
    logger: Logger,

    /// Encrypts a QueryRequest for each individual Fog View Store.
    /// TODO: Use a BTreeMap<FogViewShardLoadBalancerID,
    /// BTreeMap<FogViewStoreId, Ready<...>>>  when implement the cursoring
    /// optimization. For right now, it's fine to leave as a Vec because a
    /// follow up PR will implement cursoring.
    store_encryptors: Mutex<Vec<Ready<Aes256Gcm>>>,
}

impl<OSC> ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    pub fn new(logger: Logger) -> Self {
        Self {
            e_tx_out_store: Mutex::new(None),
            store_encryptors: Mutex::new(Vec::new()),
            ake: Default::default(),
            logger,
        }
    }
}

impl<OSC> ReportableEnclave for ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn new_ereport(&self, qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        Ok(self.ake.new_ereport(qe_info)?)
    }

    fn verify_quote(&self, quote: Quote, qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        Ok(self.ake.verify_quote(quote, qe_report)?)
    }

    fn verify_ias_report(&self, ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        self.ake.verify_ias_report(ias_report)?;
        Ok(())
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        Ok(self.ake.get_ias_report()?)
    }
}

impl<OSC> ViewEnclaveApi for ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn init(&self, params: ViewEnclaveInitParams) -> Result<()> {
        // Note: eid is passed to sgx_enclave_id crate earlier in the system, because
        // that crate is not under sgx_compat and isn't meant to be used outside of
        // enclave
        self.ake.init(Default::default(), params.self_client_id)?;
        {
            let mut lk = self.e_tx_out_store.lock()?;
            *lk = Some(ETxOutStore::new(
                params.desired_capacity,
                self.logger.clone(),
            ));
        }
        Ok(())
    }

    // AKE-related

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    // View-Enclave specific
    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        Ok(self.ake.client_accept(req)?)
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        self.ake.client_close(channel_id)?;
        Ok(())
    }

    fn query(
        &self,
        msg: EnclaveMessage<ClientSession>,
        untrusted_query_response: UntrustedQueryResponse,
    ) -> Result<Vec<u8>> {
        let channel_id = msg.channel_id.clone();
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let req: QueryRequest = mc_util_serial::decode(&user_plaintext).map_err(|e| {
            log::error!(self.logger, "Could not decode user request: {}", e);
            Error::ProstDecode
        })?;

        // Prepare the untrusted part of the response.
        let mut missed_block_ranges = Vec::new();
        let mut rng_records = Vec::new();
        let mut decommissioned_ingest_invocations = Vec::new();

        for event in untrusted_query_response.user_events.into_iter() {
            match event {
                FogUserEvent::NewRngRecord(rng_record) => rng_records.push(rng_record),

                FogUserEvent::DecommissionIngestInvocation(decommissioned_ingest_invocation) => {
                    decommissioned_ingest_invocations.push(decommissioned_ingest_invocation)
                }

                FogUserEvent::MissingBlocks(range) => missed_block_ranges.push(range),
            }
        }

        let mut resp = QueryResponse {
            highest_processed_block_count: untrusted_query_response.highest_processed_block_count,
            highest_processed_block_signature_timestamp: untrusted_query_response
                .highest_processed_block_signature_timestamp,
            next_start_from_user_event_id: untrusted_query_response.next_start_from_user_event_id,
            missed_block_ranges,
            rng_records,
            decommissioned_ingest_invocations,
            tx_out_search_results: Default::default(),
            last_known_block_count: untrusted_query_response.last_known_block_count,
            last_known_block_cumulative_txo_count: untrusted_query_response
                .last_known_block_cumulative_txo_count,
        };

        // Do the txos part, scope lock of e_tx_out_store
        {
            let mut lk = self.e_tx_out_store.lock()?;
            let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;

            resp.tx_out_search_results = req
                .get_txos
                .iter()
                .map(|key| store.find_record(&key[..]))
                .collect();
        }

        let response_plaintext_bytes = mc_util_serial::encode(&resp);

        let response = self
            .ake
            .client_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response.data)
    }

    fn add_records(&self, records: Vec<ETxOutRecord>) -> Result<()> {
        let mut lk = self.e_tx_out_store.lock()?;
        let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        for rec in records {
            store.add_record(&rec.search_key, &rec.payload)?;
        }

        Ok(())
    }

    /// Takes in a client's query request and returns a list of query requests
    /// to be sent off to each Fog View Store shard.
    fn create_multi_view_store_query_data(
        &self,
        client_query: EnclaveMessage<ClientSession>,
    ) -> Result<Vec<EnclaveMessage<ClientSession>>> {
        let client_query_bytes = self.ake.client_decrypt(client_query.clone())?;

        let mut encryptors = self.store_encryptors.lock()?;
        let mut results = Vec::with_capacity(encryptors.len());
        for store_encryptor in encryptors.deref_mut() {
            let aad = client_query.aad.clone();
            let data = store_encryptor.encrypt(&aad, &client_query_bytes)?;
            let channel_id = client_query.channel_id.clone();
            results.push(EnclaveMessage {
                aad,
                channel_id,
                data,
            });
        }

        Ok(results)
    }
}
