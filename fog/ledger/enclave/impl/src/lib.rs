// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Ledger Service Internal Enclave Implementation
//!
//! This crate implements the inside-the-enclave version of the LedgerEnclave
//! trait, which would traditionally be inside the ledger_enclave crate. This,
//! combined with a form of dependency injection, would provide the machines
//! with all the unit testing they would ever need. Fate, it seems, has a sense
//! of irony...

#![no_std]
#![deny(missing_docs)]
extern crate alloc;

mod key_image_store;
use alloc::{collections::BTreeMap, vec::Vec};
use core::cmp::max;
use key_image_store::{KeyImageStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, SealedClientMessage,
};
use mc_blockchain_types::MAX_BLOCK_VERSION;
use mc_common::{
    logger::{log, Logger},
    ResponderId,
};
use mc_crypto_ake_enclave::{AkeEnclaveState, NullIdentity};
use mc_crypto_keys::X25519Public;
use mc_fog_ledger_enclave_api::{
    Error, KeyImageData, LedgerEnclave, OutputContext, Result, UntrustedKeyImageQueryResponse,
};
use mc_fog_types::ledger::{
    CheckKeyImagesRequest, CheckKeyImagesResponse, GetOutputsRequest, GetOutputsResponse,
};
use mc_oblivious_traits::ORAMStorageCreator;
use mc_sgx_compat::sync::Mutex;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};

/// In-enclave state associated to the ledger enclaves
pub struct SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// The encrypted storage
    key_image_store: Mutex<Option<KeyImageStore<OSC>>>,

    /// The enclave state
    ake: AkeEnclaveState<NullIdentity>,

    /// Logger object
    logger: Logger,
}

/// Implementation of the sgx ledger enclave
impl<OSC> SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    /// Constructor function for the ledger enclave
    pub fn new(logger: Logger) -> Self {
        Self {
            key_image_store: Mutex::new(None),
            ake: Default::default(),
            logger,
        }
    }
}

/// Implementation of the reportable enclave for sgxledger enclave
impl<OSC> ReportableEnclave for SgxLedgerEnclave<OSC>
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

/// Implemenation for ledger encave for sgx ledger enclave
impl<OSC> LedgerEnclave for SgxLedgerEnclave<OSC>
where
    OSC: ORAMStorageCreator<StorageDataSize, StorageMetaSize>,
{
    fn enclave_init(&self, self_id: &ResponderId, desired_capacity: u64) -> Result<()> {
        self.ake.init(Default::default(), self_id.clone())?;
        let mut lk = self.key_image_store.lock()?;

        *lk = Some(KeyImageStore::new(desired_capacity, self.logger.clone()));
        Ok(())
    }

    fn get_identity(&self) -> Result<X25519Public> {
        Ok(self.ake.get_kex_identity())
    }

    fn client_accept(&self, req: ClientAuthRequest) -> Result<(ClientAuthResponse, ClientSession)> {
        Ok(self.ake.client_accept(req)?)
    }

    fn client_close(&self, channel_id: ClientSession) -> Result<()> {
        Ok(self.ake.client_close(channel_id)?)
    }

    fn get_outputs(&self, msg: EnclaveMessage<ClientSession>) -> Result<OutputContext> {
        let request_bytes = self.ake.client_decrypt(msg)?;

        // Try and deserialize.
        let enclave_request: GetOutputsRequest = mc_util_serial::decode(&request_bytes)?;

        let output_context = OutputContext {
            indexes: enclave_request.indices,
            merkle_root_block: enclave_request.merkle_root_block,
        };

        Ok(output_context)
    }

    fn get_outputs_data(
        &self,
        response: GetOutputsResponse,
        client: ClientSession,
    ) -> Result<EnclaveMessage<ClientSession>> {
        // Serialize this for the client.
        let response_bytes = mc_util_serial::encode(&response);

        // Encrypt for the client.
        Ok(self.ake.client_encrypt(&client, &[], &response_bytes)?)
    }

    fn check_key_images(
        &self,
        msg: EnclaveMessage<ClientSession>,
        untrusted_key_image_query_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>> {
        let channel_id = msg.channel_id.clone(); //client session does not implement copy trait so clone
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let req: CheckKeyImagesRequest = mc_util_serial::decode(&user_plaintext).map_err(|e| {
            log::error!(self.logger, "Could not decode user request: {}", e);
            Error::ProstDecode
        })?;

        let mut resp = CheckKeyImagesResponse {
            num_blocks: untrusted_key_image_query_response.highest_processed_block_count,
            results: Default::default(),
            global_txo_count: untrusted_key_image_query_response
                .last_known_block_cumulative_txo_count,
            latest_block_version: untrusted_key_image_query_response.latest_block_version,
            max_block_version: untrusted_key_image_query_response.max_block_version,
        };

        // Do the scope lock of keyimagetore
        {
            let mut lk = self.key_image_store.lock()?;
            let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;

            resp.results = req
                .queries
                .iter() //  get the key images used to find the key image data using the oram
                .map(|key| store.find_record(&key.key_image))
                .collect();
        }

        let response_plaintext_bytes = mc_util_serial::encode(&resp);

        let response = self
            .ake
            .client_encrypt(&channel_id, &[], &response_plaintext_bytes)?;

        Ok(response.data)
    }

    // Add a key image data to the oram using the key image
    fn add_key_image_data(&self, records: Vec<KeyImageData>) -> Result<()> {
        let mut lk = self.key_image_store.lock()?;
        let store = lk.as_mut().ok_or(Error::EnclaveNotInitialized)?;
        // add KeyImageData record to ledger oram
        for rec in records {
            store.add_record(&rec.key_image, rec.block_index, rec.timestamp)?;
        }

        Ok(())
    }

    fn connect_to_key_image_store(
        &self,
        ledger_store_id: ResponderId,
    ) -> Result<ClientAuthRequest> {
        mc_sgx_debug::eprintln!(
            "Called connect_to_key_image_store(ledger_store_id: {})",
            ledger_store_id
        );
        Ok(self.ake.backend_init(ledger_store_id)?)
    }

    #[allow(unused_variables)]
    fn finish_connecting_to_key_image_store(
        &self,
        ledger_store_id: ResponderId,
        ledger_store_auth_response: ClientAuthResponse,
    ) -> Result<()> {
        mc_sgx_debug::eprintln!("Called finish_connecting_to_key_image_store(ledger_store_id: {}, ledger_store_auth_response: {:?})", ledger_store_id, ledger_store_auth_response);
        Ok(self
            .ake
            .backend_connect(ledger_store_id, ledger_store_auth_response)?)
    }

    fn decrypt_and_seal_query(
        &self,
        client_query: EnclaveMessage<ClientSession>,
    ) -> Result<SealedClientMessage> {
        Ok(self.ake.decrypt_client_message_for_enclave(client_query)?)
    }

    fn create_multi_key_image_store_query_data(
        &self,
        sealed_query: SealedClientMessage,
    ) -> Result<Vec<EnclaveMessage<ClientSession>>> {
        mc_sgx_debug::eprintln!("Called create_multi_key_image_store_query_data(..)");
        Ok(self
            .ake
            .reencrypt_sealed_message_for_backends(&sealed_query)?)
    }

    fn collate_shard_query_responses(
        &self,
        sealed_query: SealedClientMessage,
        shard_query_responses: BTreeMap<ResponderId, EnclaveMessage<ClientSession>>,
    ) -> Result<EnclaveMessage<ClientSession>> {
        if shard_query_responses.is_empty() {
            return Ok(EnclaveMessage::default());
        }
        let channel_id = sealed_query.channel_id.clone();
        let client_query_plaintext = self.ake.unseal(&sealed_query)?;
        // TODO this will (possibly?) be used when we implement obliviousness
        let _client_query_request: CheckKeyImagesRequest =
            mc_util_serial::decode(&client_query_plaintext).map_err(|e| {
                log::error!(self.logger, "Could not decode client query request: {}", e);
                Error::ProstDecode
            })?;

        let shard_query_responses = shard_query_responses
            .into_iter()
            .map(|(responder_id, enclave_message)| {
                let plaintext_bytes = self.ake.backend_decrypt(responder_id, enclave_message)?; // TODO explicit nonces
                let query_response: CheckKeyImagesResponse =
                    mc_util_serial::decode(&plaintext_bytes)?;

                Ok(query_response)
            })
            .collect::<Result<Vec<CheckKeyImagesResponse>>>()?;

        // NOTES:
        // num_blocks = min(responses.num_blocks)
        // global_txo_count = min(global_txo_count) TODO CONFIRM
        // results = cat(responses.results)
        // latest_block_version = max(responses.latest_block_version)
        // max_block_version = max(latest_block_version,
        // mc_transaction_core::MAX_BLOCK_VERSION

        // TODO no unwraps
        let num_blocks = shard_query_responses
            .iter()
            .map(|query_response| query_response.num_blocks)
            .min()
            .unwrap();
        let global_txo_count = shard_query_responses
            .iter()
            .map(|query_response| query_response.global_txo_count)
            .min()
            .unwrap();
        let latest_block_version = shard_query_responses
            .iter()
            .map(|query_response| query_response.latest_block_version)
            .max()
            .unwrap();
        // TODO I believe this needs to be implemented in an oblivious way to meet the
        // security requirements. I'm not 100% sure what an oblivious approach
        // to this looks like, though. In general this kind of thing needs to be
        // talked about.
        let results = shard_query_responses
            .into_iter()
            .flat_map(|query_response| query_response.results)
            .collect();
        let max_block_version = max(latest_block_version, *MAX_BLOCK_VERSION);

        let client_query_response = CheckKeyImagesResponse {
            num_blocks,
            global_txo_count,
            results,
            latest_block_version,
            max_block_version,
        };
        let response_plaintext_bytes = mc_util_serial::encode(&client_query_response);
        let response =
            self.ake
                .client_encrypt(&channel_id, &sealed_query.aad, &response_plaintext_bytes)?;

        Ok(response)
    }

    fn handle_key_image_store_request(
        &self,
        _: EnclaveMessage<ClientSession>,
    ) -> Result<EnclaveMessage<ClientSession>> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_image_store::KeyImageStore;
    use mc_common::logger::create_root_logger;
    use mc_fog_ledger_enclave_api::KeyImageData;
    use mc_oblivious_traits::HeapORAMStorageCreator;
    use mc_transaction_core::ring_signature::KeyImage;
    // Test that we were able to add key image record to the oram
    #[test]
    fn test_add_record() {
        let desired_capacity: u64 = 1024 * 1024;
        let logger = create_root_logger();
        // create a new keyimagestore
        let mut key_image_store =
            KeyImageStore::<HeapORAMStorageCreator>::new(desired_capacity, logger);

        // create test KeyImageData records to store sample block_index and timestamp
        // records to be added to oram
        let rec = KeyImageData {
            key_image: KeyImage::from(2),
            block_index: 15968249514437158236,
            timestamp: 14715610560481527175,
        };

        let rec2 = KeyImageData {
            key_image: KeyImage::from(2),
            block_index: 15867249514237159136,
            timestamp: 14315610570481526166,
        };

        let rec3 = KeyImageData {
            key_image: KeyImage::from(2),
            block_index: 14978249314436157236,
            timestamp: 14613610561491525175,
        };

        // add test KeyImageData record to ledger oram
        let v_result1 = key_image_store.add_record(&rec.key_image, rec.block_index, rec.timestamp);

        assert!(v_result1.is_ok());

        //query the ledger oram for the record using the key_image
        let v = key_image_store.find_record(&rec.key_image);

        // this test should pass since we added this rec into the oram
        assert_eq!(rec.block_index, v.spent_at);
        assert_eq!(rec.timestamp, v.timestamp);
        assert_eq!(
            v.key_image_result_code,
            mc_fog_types::ledger::KeyImageResultCode::Spent as u32
        );

        // add test KeyImageData record to ledger oram
        let v_result2 =
            key_image_store.add_record(&rec2.key_image, rec2.block_index, rec2.timestamp);

        assert!(v_result2.is_ok());

        //query the ledger oram for the record using the key_image
        let v2 = key_image_store.find_record(&rec2.key_image);

        // this test should pass since we added this rec into the oram
        assert_eq!(rec2.block_index, v2.spent_at);
        assert_eq!(rec2.timestamp, v2.timestamp);
        assert_eq!(
            v2.key_image_result_code,
            mc_fog_types::ledger::KeyImageResultCode::Spent as u32
        );

        let v_result3 =
            key_image_store.add_record(&rec3.key_image, rec3.block_index, rec3.timestamp);

        assert!(v_result3.is_ok());
        //we can add the record even if the key image is all zero bytes
        let rec3 = KeyImageData {
            key_image: KeyImage::from(0),
            block_index: 14978249314436157236,
            timestamp: 14613610561491525175,
        };

        let v_result =
            key_image_store.add_record(&rec3.key_image, rec3.block_index, rec3.timestamp);

        // we should not get back "invalid key" error
        assert!(v_result.is_ok());

        //query the ledger oram for the record using the key_image
        let v3 = key_image_store.find_record(&rec3.key_image);

        // this test should pass since we added this rec into the oram
        assert_eq!(rec3.block_index, v3.spent_at);
        assert_eq!(rec3.timestamp, v3.timestamp);
        assert_eq!(
            v3.key_image_result_code,
            mc_fog_types::ledger::KeyImageResultCode::Spent as u32
        );

        //query the ledger oram for the record using the key_image not added
        let v_keyimagenotfound = key_image_store.find_record(&KeyImage::from(4));
        assert_eq!(
            v_keyimagenotfound.key_image_result_code,
            mc_fog_types::ledger::KeyImageResultCode::NotSpent as u32
        );
    }
}
