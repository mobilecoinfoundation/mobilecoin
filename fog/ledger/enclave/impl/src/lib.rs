// Copyright (c) 2018-2021 The MobileCoin Foundation

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
use alloc::vec::Vec;
use key_image_store::{KeyImageStore, StorageDataSize, StorageMetaSize};
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
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
        untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>> {
        let channel_id = msg.channel_id.clone(); //client session does not implement copy trait so clone
        let user_plaintext = self.ake.client_decrypt(msg)?;

        let req: CheckKeyImagesRequest = mc_util_serial::decode(&user_plaintext).map_err(|e| {
            log::error!(self.logger, "Could not decode user request: {}", e);
            Error::ProstDecode
        })?;

        let mut resp = CheckKeyImagesResponse {
            num_blocks: untrusted_keyimagequery_response.highest_processed_block_count,
            results: Default::default(),
            global_txo_count: untrusted_keyimagequery_response
                .last_known_block_cumulative_txo_count,
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

        assert!(v_result1.is_ok() && !v_result1.is_err());

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

        assert!(v_result2.is_ok() && !v_result2.is_err());

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

        assert!(v_result3.is_ok() && !v_result3.is_err());
        //we can add the record even if the key image is all zero bytes
        let rec3 = KeyImageData {
            key_image: KeyImage::from(0),
            block_index: 14978249314436157236,
            timestamp: 14613610561491525175,
        };

        let v_result =
            key_image_store.add_record(&rec3.key_image, rec3.block_index, rec3.timestamp);

        // we should not get back "invalid key" error
        assert!(!v_result.is_err());

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
