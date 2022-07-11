// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Functionality for mocking and testing components in the ledger server

use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage};
use mc_blockchain_types::{
    Block, BlockContents, BlockData, BlockIndex, BlockMetadata, BlockSignature,
};
use mc_common::{HashMap, ResponderId};
use mc_crypto_keys::{CompressedRistrettoPublic, X25519Public};
use mc_fog_ledger_enclave::{
    GetOutputsResponse, LedgerEnclave, OutputContext, Result as EnclaveResult,
};
use mc_fog_ledger_enclave_api::{KeyImageData, UntrustedKeyImageQueryResponse};
use mc_ledger_db::{ActiveMintConfig, ActiveMintConfigs, Error, Ledger};
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_transaction_core::{
    mint::MintTx,
    ring_signature::KeyImage,
    tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
    TokenId,
};

#[derive(Default, Clone)]
pub struct MockEnclave {}

impl ReportableEnclave for MockEnclave {
    fn new_ereport(&self, _qe_info: TargetInfo) -> ReportableEnclaveResult<(Report, QuoteNonce)> {
        Ok((Report::default(), QuoteNonce::default()))
    }

    fn verify_quote(&self, _quote: Quote, _qe_report: Report) -> ReportableEnclaveResult<IasNonce> {
        Ok(IasNonce::default())
    }

    fn verify_ias_report(&self, _ias_report: VerificationReport) -> ReportableEnclaveResult<()> {
        Ok(())
    }

    fn get_ias_report(&self) -> ReportableEnclaveResult<VerificationReport> {
        Ok(VerificationReport::default())
    }
}

impl LedgerEnclave for MockEnclave {
    fn enclave_init(&self, _self_id: &ResponderId, _desired_capacity: u64) -> EnclaveResult<()> {
        unimplemented!()
    }

    fn get_identity(&self) -> EnclaveResult<X25519Public> {
        unimplemented!()
    }
    fn client_accept(
        &self,
        _req: ClientAuthRequest,
    ) -> EnclaveResult<(ClientAuthResponse, ClientSession)> {
        unimplemented!()
    }
    fn client_close(&self, _channel_id: ClientSession) -> EnclaveResult<()> {
        unimplemented!()
    }
    fn get_outputs(&self, _msg: EnclaveMessage<ClientSession>) -> EnclaveResult<OutputContext> {
        unimplemented!()
    }
    fn get_outputs_data(
        &self,
        _outputs: GetOutputsResponse,
        _client: ClientSession,
    ) -> EnclaveResult<EnclaveMessage<ClientSession>> {
        unimplemented!()
    }
    fn check_key_images(
        &self,
        _msg: EnclaveMessage<ClientSession>,
        _untrusted_keyimagequery_response: UntrustedKeyImageQueryResponse,
    ) -> Result<Vec<u8>, mc_fog_ledger_enclave::Error> {
        unimplemented!()
    }

    fn add_key_image_data(
        &self,
        _records: Vec<KeyImageData>,
    ) -> Result<(), mc_fog_ledger_enclave::Error> {
        unimplemented!()
    }
}

#[derive(Clone, Default)]
pub struct MockLedger {
    pub tx_out_by_index: HashMap<u64, TxOut>,
    pub tx_out_index_by_hash: HashMap<[u8; 32], u64>,
    pub tx_out_membership_proof_by_index: HashMap<u64, TxOutMembershipProof>,
    pub num_blocks: u64,
    pub num_tx_outs: u64,
}

impl Ledger for MockLedger {
    fn append_block<'b>(
        &mut self,
        _block: &'b Block,
        _block_contents: &'b BlockContents,
        _signature: Option<&'b BlockSignature>,
        _metadata: Option<&'b BlockMetadata>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    fn num_blocks(&self) -> Result<u64, Error> {
        Ok(self.num_blocks)
    }

    fn get_block(&self, block_number: u64) -> Result<Block, Error> {
        if block_number < self.num_blocks {
            Ok(Block::default())
        } else {
            Err(Error::NotFound)
        }
    }

    fn get_block_signature(&self, _block_number: u64) -> Result<BlockSignature, Error> {
        unimplemented!()
    }

    fn get_block_metadata(&self, _block_number: u64) -> Result<BlockMetadata, Error> {
        unimplemented!()
    }

    fn get_block_data(&self, _block_number: u64) -> Result<BlockData, Error> {
        unimplemented!()
    }

    fn num_txos(&self) -> Result<u64, Error> {
        Ok(self.num_tx_outs)
    }

    fn get_tx_out_index_by_hash(&self, tx_out_hash: &[u8; 32]) -> Result<u64, Error> {
        match self.tx_out_index_by_hash.get(tx_out_hash) {
            Some(index) => Ok(*index),
            None => Err(Error::NotFound),
        }
    }

    fn get_tx_out_by_index(&self, index: u64) -> Result<TxOut, Error> {
        match self.tx_out_by_index.get(&index) {
            Some(tx_out) => Ok(tx_out.clone()),
            None => Err(Error::NotFound),
        }
    }

    fn get_tx_out_proof_of_memberships(
        &self,
        indexes: &[u64],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        indexes
            .iter()
            .map(
                |index| match self.tx_out_membership_proof_by_index.get(index) {
                    Some(proof) => Ok(proof.clone()),
                    None => Err(Error::NotFound),
                },
            )
            .collect()
    }

    fn check_key_image(&self, _key_image: &KeyImage) -> Result<Option<u64>, Error> {
        unimplemented!()
    }

    fn get_key_images_by_block(&self, _block_number: u64) -> Result<Vec<KeyImage>, Error> {
        unimplemented!()
    }

    fn get_block_contents(&self, _block_number: u64) -> Result<BlockContents, Error> {
        unimplemented!()
    }

    fn contains_tx_out_public_key(
        &self,
        _public_key: &CompressedRistrettoPublic,
    ) -> Result<bool, Error> {
        unimplemented!();
    }

    fn get_tx_out_index_by_public_key(
        &self,
        _tx_out_public_key: &CompressedRistrettoPublic,
    ) -> Result<u64, Error> {
        unimplemented!();
    }

    fn get_block_index_by_tx_out_index(&self, _tx_out_index: u64) -> Result<u64, Error> {
        unimplemented!()
    }

    fn get_root_tx_out_membership_element(&self) -> Result<TxOutMembershipElement, Error> {
        unimplemented!()
    }

    fn get_active_mint_configs(
        &self,
        _token_id: TokenId,
    ) -> Result<Option<ActiveMintConfigs>, Error> {
        unimplemented!()
    }

    fn get_active_mint_configs_map(&self) -> Result<HashMap<TokenId, ActiveMintConfigs>, Error> {
        unimplemented!()
    }

    fn check_mint_config_tx_nonce(&self, _nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        unimplemented!()
    }

    fn check_mint_tx_nonce(&self, _nonce: &[u8]) -> Result<Option<BlockIndex>, Error> {
        unimplemented!()
    }

    fn get_active_mint_config_for_mint_tx(
        &self,
        _mint_tx: &MintTx,
    ) -> Result<ActiveMintConfig, Error> {
        unimplemented!()
    }
}
