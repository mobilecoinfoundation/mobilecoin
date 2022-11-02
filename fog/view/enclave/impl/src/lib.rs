// Copyright (c) 2018-2022 The MobileCoin Foundation

//! View Enclave Implementation

#![no_std]

extern crate alloc;

mod e_tx_out_store;
mod oblivious_utils;
mod types;

use alloc::vec::Vec;
use e_tx_out_store::{ETxOutStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, NonceAuthRequest,
    NonceAuthResponse, NonceSession, SealedClientMessage,
};
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_fog_recovery_db_iface::FogUserEvent;
use mc_fog_types::{
    view::{MultiViewStoreQueryResponse, QueryRequest, QueryResponse, TxOutSearchResult},
    ETxOutRecord,
};
use mc_fog_view_enclave_api::{
    Error, Result, UntrustedQueryResponse, ViewEnclaveApi, ViewEnclaveInitParams,
};
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use types::{BlockData, CommonShardData, DecryptedMultiViewStoreQueryResponse, LastKnownData};

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
}

impl<OSC> ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    pub fn new(logger: Logger) -> Self {
        Self {
            e_tx_out_store: Mutex::new(None),
            ake: Default::default(),
            logger,
        }
    }

    fn query_impl(
        &self,
        plaintext_request: &[u8],
        untrusted_query_response: UntrustedQueryResponse,
    ) -> Result<Vec<u8>> {
        let req: QueryRequest = mc_util_serial::decode(plaintext_request).map_err(|e| {
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
        Ok(response_plaintext_bytes)
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
        let response_plaintext_bytes =
            self.query_impl(&user_plaintext, untrusted_query_response)?;
        let response = self
            .ake
            .client_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response.data)
    }

    fn query_store(
        &self,
        msg: EnclaveMessage<NonceSession>,
        untrusted_query_response: UntrustedQueryResponse,
    ) -> Result<EnclaveMessage<NonceSession>> {
        let channel_id = msg.channel_id.clone();
        let user_plaintext = self.ake.frontend_decrypt(msg)?;
        let response_plaintext_bytes =
            self.query_impl(&user_plaintext, untrusted_query_response)?;
        let response = self
            .ake
            .frontend_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response)
    }

    fn add_records(&self, records: Vec<ETxOutRecord>) -> Result<()> {
        let mut lk = self.e_tx_out_store.lock()?;
        let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        for rec in records {
            store.add_record(&rec.search_key, &rec.payload)?;
        }

        Ok(())
    }

    /// Decrypts a client query message and converts it into a
    /// SealedClientMessage which can be unsealed multiple times to
    /// construct the MultiViewStoreQuery.
    fn decrypt_and_seal_query(
        &self,
        client_query: EnclaveMessage<ClientSession>,
    ) -> Result<SealedClientMessage> {
        Ok(self.ake.decrypt_client_message_for_enclave(client_query)?)
    }

    /// Takes in a client's query request and returns a list of query requests
    /// to be sent off to each Fog View Store shard.
    fn create_multi_view_store_query_data(
        &self,
        sealed_query: SealedClientMessage,
    ) -> Result<Vec<EnclaveMessage<NonceSession>>> {
        Ok(self
            .ake
            .reencrypt_sealed_message_for_backends(&sealed_query)?)
    }

    fn view_store_init(&self, view_store_id: ResponderId) -> Result<NonceAuthRequest> {
        Ok(self.ake.backend_init(view_store_id)?)
    }

    fn view_store_connect(
        &self,
        view_store_id: ResponderId,
        view_store_auth_response: NonceAuthResponse,
    ) -> Result<()> {
        Ok(self
            .ake
            .backend_connect(view_store_id, view_store_auth_response)?)
    }

    fn frontend_accept(&self, req: NonceAuthRequest) -> Result<(NonceAuthResponse, NonceSession)> {
        Ok(self.ake.frontend_accept(req)?)
    }

    fn collate_shard_query_responses(
        &self,
        sealed_query: SealedClientMessage,
        shard_query_responses: Vec<MultiViewStoreQueryResponse>,
    ) -> Result<EnclaveMessage<ClientSession>> {
        if shard_query_responses.is_empty() {
            return Ok(EnclaveMessage::default());
        }
        let channel_id = sealed_query.channel_id.clone();
        let client_query_plaintext = self.ake.unseal(&sealed_query)?;
        let client_query_request: QueryRequest = mc_util_serial::decode(&client_query_plaintext)
            .map_err(|e| {
                log::error!(self.logger, "Could not decode client query request: {}", e);
                Error::ProstDecode
            })?;

        let client_query_response =
            self.create_client_query_response(client_query_request, shard_query_responses)?;
        let response_plaintext_bytes = mc_util_serial::encode(&client_query_response);
        let response =
            self.ake
                .client_encrypt(&channel_id, &sealed_query.aad, &response_plaintext_bytes)?;

        Ok(response)
    }
}

impl<OSC> ViewEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn create_client_query_response(
        &self,
        client_query_request: QueryRequest,
        shard_query_responses: Vec<MultiViewStoreQueryResponse>,
    ) -> Result<QueryResponse> {
        // Choose any shard query response and use it to supply the skeleton values for
        // the QueryResponse. The tx_out_search_results and
        // highest_processed_block_count fields will be set based on all of the
        // shard query responses.
        let shard_query_response = shard_query_responses
            .first()
            .expect("Shard query responses must have at least one response.");
        let shard_query_response_plaintext = self.ake.backend_decrypt(
            &shard_query_response.store_responder_id,
            &shard_query_response.encrypted_query_response,
        )?;
        let mut shard_query_response: QueryResponse =
            mc_util_serial::decode(&shard_query_response_plaintext).map_err(|e| {
                log::error!(self.logger, "Could not decode shard query response: {}", e);
                Error::ProstDecode
            })?;

        let shard_query_responses = shard_query_responses
            .into_iter()
            .map(|multi_view_store_query_response| {
                let plaintext_bytes = self.ake.backend_decrypt(
                    &multi_view_store_query_response.store_responder_id,
                    &multi_view_store_query_response.encrypted_query_response,
                )?;
                let query_response: QueryResponse = mc_util_serial::decode(&plaintext_bytes)?;

                Ok(DecryptedMultiViewStoreQueryResponse {
                    query_response,
                    block_range: multi_view_store_query_response.block_range,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        shard_query_response.tx_out_search_results =
            Self::get_collated_tx_out_search_results(client_query_request, &shard_query_responses)?;
        let last_known_data = get_last_known_data(&shard_query_responses);
        shard_query_response.last_known_block_count = last_known_data.last_known_block_count;
        shard_query_response.last_known_block_cumulative_txo_count =
            last_known_data.last_known_block_cumulative_txo_count;
        let shared_data: CommonShardData = shard_query_responses.as_slice().into();
        shard_query_response.missed_block_ranges = shared_data.missed_block_ranges;
        shard_query_response.rng_records = shared_data.rng_records;
        shard_query_response.decommissioned_ingest_invocations =
            shared_data.decommissioned_ingest_invocations;
        shard_query_response.next_start_from_user_event_id =
            shared_data.next_start_from_user_event_id;

        let block_data = get_block_data(shard_query_responses);
        shard_query_response.highest_processed_block_count =
            block_data.highest_processed_block_count;
        shard_query_response.highest_processed_block_signature_timestamp =
            block_data.highest_processed_block_signature_timestamp;

        Ok(shard_query_response)
    }

    fn get_collated_tx_out_search_results(
        client_query_request: QueryRequest,
        shard_query_responses: &[DecryptedMultiViewStoreQueryResponse],
    ) -> Result<Vec<TxOutSearchResult>> {
        let plaintext_search_results = shard_query_responses
            .iter()
            .flat_map(|response| response.query_response.tx_out_search_results.clone())
            .collect::<Vec<TxOutSearchResult>>();

        oblivious_utils::collate_shard_tx_out_search_results(
            client_query_request.get_txos,
            plaintext_search_results,
        )
    }
}

fn get_block_data(mut responses: Vec<DecryptedMultiViewStoreQueryResponse>) -> BlockData {
    responses.sort_unstable_by_key(|response| response.block_range.start_block);

    // Find the first time in which a highest processed block count does not equate
    // to the final block that the shard is responsible for.
    let mut result = BlockData::default();
    for response in responses.iter() {
        let response_highest_processed_block_count =
            response.query_response.highest_processed_block_count;
        if response_highest_processed_block_count > result.highest_processed_block_count {
            result = BlockData::new(
                response_highest_processed_block_count,
                response
                    .query_response
                    .highest_processed_block_signature_timestamp,
            );
        }

        // In this case, the shard hasn't processed all the blocks it's responsible for,
        // and, as such, those blocks might not be processed so we should return this
        // number.
        // TODO: Consider implementing logic that accounts for overlapping block ranges.
        //   If ranges overlap, then the next server might have processed those blocks
        //   that this shard did not process (but is responsible for).
        if response_highest_processed_block_count < response.block_range.end_block {
            return result;
        }
    }

    result
}

fn get_last_known_data(responses: &[DecryptedMultiViewStoreQueryResponse]) -> LastKnownData {
    responses
        .iter()
        .max_by_key(|response| response.query_response.last_known_block_count)
        .map_or_else(LastKnownData::default, |response| {
            LastKnownData::new(
                response.query_response.last_known_block_count,
                response
                    .query_response
                    .last_known_block_cumulative_txo_count,
            )
        })
}

#[cfg(test)]
mod get_block_data_tests {
    use crate::{get_block_data, DecryptedMultiViewStoreQueryResponse};
    use alloc::{vec, vec::Vec};
    use mc_fog_types::{common::BlockRange, view::QueryResponse};

    fn create_query_response(
        highest_processed_block_count: u64,
        highest_processed_block_signature_timestamp: u64,
    ) -> QueryResponse {
        QueryResponse {
            highest_processed_block_count,
            highest_processed_block_signature_timestamp,
            next_start_from_user_event_id: 0,
            missed_block_ranges: vec![],
            rng_records: vec![],
            decommissioned_ingest_invocations: vec![],
            tx_out_search_results: vec![],
            last_known_block_count: highest_processed_block_count,
            last_known_block_cumulative_txo_count: 0,
        }
    }

    #[test]
    fn all_responses_fully_processed() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let query_response = create_query_response((i + 1) as u64, i as u64);
            let block_range = BlockRange::new(i as u64, (i + 1) as u64);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let result = get_block_data(decrypted_query_responses.clone());

        let last_response = decrypted_query_responses.last().unwrap();
        assert_eq!(
            result.highest_processed_block_count,
            last_response.query_response.highest_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            last_response
                .query_response
                .highest_processed_block_signature_timestamp
        );
    }

    #[test]
    fn first_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response "incomplete"- i.e. it hasn't processed all of its
        // blocks.
        let incomplete_query_response = create_query_response(2, 2);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response.clone(),
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(12, 12);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(
            result.highest_processed_block_count,
            incomplete_query_response.highest_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_query_response.highest_processed_block_signature_timestamp
        );
    }

    #[test]
    fn second_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let fully_processed_block_count = 3;
        let fully_processed_timestamp = 3;
        let query_response =
            create_query_response(fully_processed_block_count, fully_processed_timestamp);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response process zero blocks.
        let query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(
            result.highest_processed_block_count,
            fully_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            fully_processed_timestamp
        );
    }
    #[test]
    fn second_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response "incomplete"- i.e. it hasn't processed all of its
        // blocks.
        let incomplete_block_count = 4;
        let incomplete_timestamp = 4;
        let incomplete_query_response =
            create_query_response(incomplete_block_count, incomplete_block_count);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn penultimate_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response incomplete.
        let incomplete_block_count = 8;
        let incomplete_timestamp = 8;
        let query_response = create_query_response(incomplete_block_count, incomplete_timestamp);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(12, 12);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn penultimate_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(1, 1);
        let block_range = BlockRange::new(0, 1);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let second_response_highest_processed_block_count = 2;
        let second_response_timestamp = 2;
        let query_response = create_query_response(
            second_response_highest_processed_block_count,
            second_response_timestamp,
        );
        let block_range = BlockRange::new(1, 2);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the third response process zero blocks.
        let incomplete_query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(2, 3);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the fourth response fully processed.
        let query_response = create_query_response(4, 4);
        let block_range = BlockRange::new(3, 4);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(
            result.highest_processed_block_count,
            second_response_highest_processed_block_count,
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            second_response_timestamp
        );
    }

    #[test]
    fn final_response_incomplete() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let query_response = create_query_response(9, 9);
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let incomplete_block_count = 10;
        let incomplete_timestamp = 10;
        let query_response = create_query_response(10, 10);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(result.highest_processed_block_count, incomplete_block_count);
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            incomplete_timestamp
        );
    }

    #[test]
    fn final_response_zero_processed_blocks() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        // Make the first response fully processed.
        let query_response = create_query_response(3, 3);
        let block_range = BlockRange::new(0, 3);
        let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        };
        decrypted_query_responses.push(decrypted_query_response);

        // Make the second response fully processed.
        let incomplete_query_response = create_query_response(6, 6);
        let block_range = BlockRange::new(3, 6);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response: incomplete_query_response,
            block_range,
        });

        // Make the third response fully processed.
        let last_fully_processed_block_count = 9;
        let last_fully_processed_timestamp = 9;
        let query_response = create_query_response(
            last_fully_processed_block_count,
            last_fully_processed_timestamp,
        );
        let block_range = BlockRange::new(6, 9);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        // Make the fourth response incomplete.
        let query_response = create_query_response(0, 0);
        let block_range = BlockRange::new(9, 12);
        decrypted_query_responses.push(DecryptedMultiViewStoreQueryResponse {
            query_response,
            block_range,
        });

        let result = get_block_data(decrypted_query_responses.clone());

        assert_eq!(
            result.highest_processed_block_count,
            last_fully_processed_block_count
        );
        assert_eq!(
            result.highest_processed_block_signature_timestamp,
            last_fully_processed_timestamp
        );
    }
}
#[cfg(test)]
mod last_known_block_data_tests {
    use crate::{get_last_known_data, DecryptedMultiViewStoreQueryResponse};
    use alloc::{vec, vec::Vec};
    use mc_fog_types::{common::BlockRange, view::QueryResponse};

    fn create_query_response(
        last_known_block_count: u64,
        last_known_block_cumulative_txo_count: u64,
    ) -> QueryResponse {
        QueryResponse {
            highest_processed_block_count: 0,
            highest_processed_block_signature_timestamp: 0,
            next_start_from_user_event_id: 0,
            missed_block_ranges: vec![],
            rng_records: vec![],
            decommissioned_ingest_invocations: vec![],
            tx_out_search_results: vec![],
            last_known_block_count,
            last_known_block_cumulative_txo_count,
        }
    }

    #[test]
    fn different_last_known_block_counts() {
        const STORE_COUNT: usize = 4;
        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);

        for i in 0..STORE_COUNT {
            let last_known_block_count = ((i + 1) * 10) as u64;
            let last_known_block_cumulative_txo_count = last_known_block_count * 2;
            let query_response = create_query_response(
                last_known_block_count,
                last_known_block_cumulative_txo_count,
            );
            let block_range = BlockRange::new(i as u64, last_known_block_count);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let last_response = decrypted_query_responses
            .last()
            .expect("Couldn't get last decrypted query response");
        let expected_last_known_block_count = last_response.query_response.last_known_block_count;
        let expected_last_known_block_cumulative_txo_count = last_response
            .query_response
            .last_known_block_cumulative_txo_count;

        let result = get_last_known_data(&decrypted_query_responses);

        assert_eq!(
            result.last_known_block_count,
            expected_last_known_block_count
        );
        assert_eq!(
            result.last_known_block_cumulative_txo_count,
            expected_last_known_block_cumulative_txo_count
        );
    }

    #[test]
    fn same_last_known_block_counts() {
        const STORE_COUNT: usize = 4;
        const LAST_KNOWN_BLOCK_COUNT: u64 = 100;
        const LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT: u64 = 1000;

        let mut decrypted_query_responses = Vec::with_capacity(STORE_COUNT);
        for i in 0..STORE_COUNT {
            let end_block_count = ((i + 1) * 25) as u64;
            let query_response = create_query_response(
                LAST_KNOWN_BLOCK_COUNT,
                LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT,
            );
            let block_range = BlockRange::new(i as u64, end_block_count);
            let decrypted_query_response = DecryptedMultiViewStoreQueryResponse {
                query_response,
                block_range,
            };
            decrypted_query_responses.push(decrypted_query_response);
        }

        let result = get_last_known_data(&decrypted_query_responses);

        assert_eq!(result.last_known_block_count, LAST_KNOWN_BLOCK_COUNT);
        assert_eq!(
            result.last_known_block_cumulative_txo_count,
            LAST_KNOWN_BLOCK_CUMULATIVE_TXO_COUNT
        );
    }
}
