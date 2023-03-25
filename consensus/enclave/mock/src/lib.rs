// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Mock enclave, used for tests

mod mock_consensus_enclave;

pub use mc_consensus_enclave_api::{
    BlockchainConfig, ConsensusEnclave, ConsensusEnclaveProxy, Error, FeePublicKey,
    FormBlockInputs, LocallyEncryptedTx, Result, SealedBlockSigningKey, TxContext,
    WellFormedEncryptedTx, WellFormedTxContext,
};
pub use mock_consensus_enclave::MockConsensusEnclave;

use mc_account_keys::PublicAddress;
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
    PeerAuthResponse, PeerSession,
};
use mc_blockchain_types::{Block, BlockContents, BlockSignature, BlockVersion};
use mc_common::ResponderId;
use mc_crypto_keys::{Ed25519Pair, Ed25519Public, RistrettoPublic, X25519Private, X25519Public};
use mc_crypto_multisig::SignerSet;
use mc_rand::{McRng, RngCore};
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_transaction_core::{
    membership_proofs::compute_implied_merkle_root,
    mint::ValidatedMintConfigTx,
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutMembershipElement, TxOutMembershipProof},
    validation::TransactionValidationError,
    Amount, Token, TokenId,
};
use mc_transaction_core_test_utils::get_outputs;
use mc_util_from_random::FromRandom;
use mc_util_test_helper::{CryptoRng, RngType as FixedRng, SeedableRng};
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct ConsensusServiceMockEnclave {
    pub signing_keypair: Arc<Ed25519Pair>,
    pub minting_trust_root_keypair: Arc<Ed25519Pair>,
    pub blockchain_config: Arc<Mutex<BlockchainConfig>>,
    pub verification_report: VerificationReport,
    pub identity: X25519Private,
}

impl Default for ConsensusServiceMockEnclave {
    fn default() -> Self {
        Self::new(BlockVersion::MAX, &mut FixedRng::seed_from_u64(0))
    }
}

impl ConsensusServiceMockEnclave {
    pub fn new(block_version: BlockVersion, csprng: &mut (impl RngCore + CryptoRng)) -> Self {
        let signing_keypair = Arc::new(Ed25519Pair::from_random(csprng));
        let minting_trust_root_keypair = Arc::new(Ed25519Pair::from_random(csprng));
        let blockchain_config = Arc::new(Mutex::new(BlockchainConfig {
            block_version,
            ..Default::default()
        }));
        let verification_report = mc_blockchain_test_utils::make_verification_report(csprng);
        let identity = X25519Private::from_random(csprng);

        Self {
            signing_keypair,
            minting_trust_root_keypair,
            blockchain_config,
            verification_report,
            identity,
        }
    }

    pub fn tx_to_tx_context(tx: &Tx) -> TxContext {
        let locally_encrypted_tx = LocallyEncryptedTx(mc_util_serial::encode(tx));
        let tx_hash = tx.tx_hash();
        let highest_indices = tx.get_membership_proof_highest_indices();
        let key_images: Vec<KeyImage> = tx.key_images();
        let output_public_keys = tx.output_public_keys();

        TxContext {
            locally_encrypted_tx,
            tx_hash,
            highest_indices,
            key_images,
            output_public_keys,
        }
    }
}

impl ReportableEnclave for ConsensusServiceMockEnclave {
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
        Ok(self.verification_report.clone())
    }
}

impl ConsensusEnclave for ConsensusServiceMockEnclave {
    fn enclave_init(
        &self,
        _self_peer_id: &ResponderId,
        _self_client_id: &ResponderId,
        _sealed_key: &Option<SealedBlockSigningKey>,
        blockchain_config: BlockchainConfig,
    ) -> Result<(SealedBlockSigningKey, Vec<String>)> {
        *self.blockchain_config.lock().unwrap() = blockchain_config;

        Ok((vec![], vec![]))
    }

    fn get_minimum_fee(&self, token_id: &TokenId) -> Result<Option<u64>> {
        Ok(self
            .blockchain_config
            .lock()
            .unwrap()
            .fee_map
            .get_fee_for_token(token_id))
    }

    fn get_identity(&self) -> Result<X25519Public> {
        Ok((&self.identity).into())
    }

    fn get_signer(&self) -> Result<Ed25519Public> {
        Ok(self.signing_keypair.public_key())
    }

    fn get_minting_trust_root(&self) -> Result<Ed25519Public> {
        Ok(self.minting_trust_root_keypair.public_key())
    }

    // NOTE: We hardcode here because we don't need the mock enclave currently to be
    // configurable       by env vars, and we also do not currently have any
    // tests verifying with the private fee key       for the mock enclave, so
    // only the public keys are listed here.
    fn get_fee_recipient(&self) -> Result<FeePublicKey> {
        let fee_spend_public_key = [
            38, 181, 7, 198, 49, 36, 162, 245, 233, 64, 180, 251, 137, 228, 178, 187, 10, 32, 120,
            237, 12, 142, 85, 26, 213, 146, 104, 185, 100, 110, 194, 65,
        ];
        let fee_view_public_key = [
            82, 34, 161, 233, 174, 50, 210, 28, 35, 17, 74, 92, 230, 187, 57, 224, 203, 86, 174,
            163, 80, 212, 97, 157, 67, 177, 32, 112, 97, 177, 3, 70,
        ];
        let spend_public_key = RistrettoPublic::try_from(&fee_spend_public_key).unwrap();
        let view_public_key = RistrettoPublic::try_from(&fee_view_public_key).unwrap();
        Ok(FeePublicKey {
            spend_public_key,
            view_public_key,
        })
    }

    fn client_accept(
        &self,
        _req: ClientAuthRequest,
    ) -> Result<(ClientAuthResponse, ClientSession)> {
        Ok((ClientAuthResponse::default(), ClientSession::default()))
    }

    fn client_close(&self, _channel_id: ClientSession) -> Result<()> {
        Ok(())
    }

    fn client_discard_message(&self, _msg: EnclaveMessage<ClientSession>) -> Result<()> {
        Ok(())
    }

    fn peer_init(&self, _node_id: &ResponderId) -> Result<PeerAuthRequest> {
        Ok(vec![].into())
    }

    fn peer_accept(&self, _req: PeerAuthRequest) -> Result<(PeerAuthResponse, PeerSession)> {
        Ok((PeerAuthResponse::default(), PeerSession::default()))
    }

    fn peer_connect(
        &self,
        _node_id: &ResponderId,
        _msg: PeerAuthResponse,
    ) -> Result<(PeerSession, VerificationReport)> {
        Ok((vec![].into(), VerificationReport::default()))
    }

    fn peer_close(&self, _msg: &PeerSession) -> Result<()> {
        Ok(())
    }

    fn client_tx_propose(&self, _msg: EnclaveMessage<ClientSession>) -> Result<TxContext> {
        Ok(TxContext::default())
    }

    fn peer_tx_propose(&self, _msg: EnclaveMessage<PeerSession>) -> Result<Vec<TxContext>> {
        Ok(Vec::default())
    }

    fn tx_is_well_formed(
        &self,
        locally_encrypted_tx: LocallyEncryptedTx,
        _block_index: u64,
        _proofs: Vec<TxOutMembershipProof>,
    ) -> Result<(WellFormedEncryptedTx, WellFormedTxContext)> {
        let tx: Tx = mc_util_serial::decode(&locally_encrypted_tx.0)?;
        let well_formed_encrypted_tx = WellFormedEncryptedTx(locally_encrypted_tx.0);

        // hack
        let priority = tx.prefix.fee;
        let well_formed_tx_context = WellFormedTxContext::from_tx(&tx, priority);

        Ok((well_formed_encrypted_tx, well_formed_tx_context))
    }

    fn txs_for_peer(
        &self,
        _encrypted_txs: &[WellFormedEncryptedTx],
        _aad: &[u8],
        _peer: &PeerSession,
    ) -> Result<EnclaveMessage<PeerSession>> {
        Ok(EnclaveMessage::default())
    }

    fn form_block(
        &self,
        parent_block: &Block,
        inputs: FormBlockInputs,
        root_element: &TxOutMembershipElement,
    ) -> Result<(Block, BlockContents, BlockSignature)> {
        let block_version = self.blockchain_config.lock().unwrap().block_version;
        let transactions_with_proofs: Vec<(Tx, Vec<TxOutMembershipProof>)> = inputs
            .well_formed_encrypted_txs_with_proofs
            .iter()
            .map(|(encrypted_tx, proofs)| {
                // These bytes are normally an enclave-encrypted Tx, but here, it is just
                // serialized.
                let ciphertext = &encrypted_tx.0;
                let tx = mc_util_serial::decode::<Tx>(ciphertext).unwrap();
                (tx, proofs.clone())
            })
            .collect();

        // root_elements contains the root hash of the Merkle tree of all TxOuts in the
        // ledger that were used to validate the tranasctions.
        let mut root_elements = Vec::new();
        let mut rng = McRng::default();

        for (tx, proofs) in transactions_with_proofs.iter() {
            mc_transaction_core::validation::validate(
                tx,
                parent_block.index + 1,
                block_version,
                proofs,
                Mob::MINIMUM_FEE,
                &mut rng,
            )?;

            for proof in proofs {
                let implied_root = compute_implied_merkle_root(proof)
                    .map_err(|_e| TransactionValidationError::InvalidLedgerContext)?;
                root_elements.push(implied_root);
            }
        }

        root_elements.sort();
        root_elements.dedup();

        if !transactions_with_proofs.is_empty()
            && (root_elements.len() != 1 || root_elements[0] != *root_element)
        {
            return Err(Error::InvalidLocalMembershipProof);
        }

        let mut key_images: Vec<KeyImage> = Vec::new();
        let mut outputs: Vec<TxOut> = Vec::new();
        for (tx, _proofs) in transactions_with_proofs {
            key_images.extend(tx.key_images().into_iter());
            outputs.extend(tx.prefix.outputs.into_iter());
        }

        let minted_tx_outs = get_outputs(
            block_version,
            &inputs
                .mint_txs_with_config
                .iter()
                .map(|(mint_tx, _mint_config_tx, _mint_config)| {
                    let recipient = PublicAddress::new(
                        &mint_tx.prefix.spend_public_key,
                        &mint_tx.prefix.view_public_key,
                    );
                    let amount = Amount::new(mint_tx.prefix.amount, mint_tx.prefix.token_id.into());
                    (recipient, amount)
                })
                .collect::<Vec<_>>(),
            &mut rng,
        );
        outputs.extend(minted_tx_outs);

        let validated_mint_config_txs = inputs
            .mint_config_txs
            .into_iter()
            .map(|mint_config_tx| ValidatedMintConfigTx {
                mint_config_tx,
                signer_set: SignerSet::default(),
            })
            .collect();

        let block_contents = BlockContents {
            key_images,
            outputs,
            mint_txs: inputs
                .mint_txs_with_config
                .into_iter()
                .map(|(mint_tx, _mint_config_tx, _mint_config)| mint_tx)
                .collect(),
            validated_mint_config_txs,
        };

        let block =
            Block::new_with_parent(block_version, parent_block, root_element, &block_contents);

        let signature = BlockSignature::from_block_and_keypair(&block, &self.signing_keypair)?;

        Ok((block, block_contents, signature))
    }
}

// Get the marker trait as well
impl ConsensusEnclaveProxy for ConsensusServiceMockEnclave {}
