// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Mock enclave, used for tests

mod mock_consensus_enclave;

pub use mock_consensus_enclave::MockConsensusEnclave;

pub use mc_consensus_enclave_api::{
    BlockchainConfig, ConsensusEnclave, ConsensusEnclaveProxy, Error, FeePublicKey,
    FormBlockInputs, LocallyEncryptedTx, Result, SealedBlockSigningKey, TxContext,
    WellFormedEncryptedTx, WellFormedTxContext,
};

use mc_account_keys::PublicAddress;
use mc_attest_core::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use mc_attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
    PeerAuthResponse, PeerSession,
};
use mc_common::ResponderId;
use mc_crypto_keys::{
    Ed25519Pair, Ed25519Public, RistrettoPublic, X25519EphemeralPrivate, X25519Public,
};
use mc_crypto_rand::McRng;
use mc_sgx_report_cache_api::{ReportableEnclave, Result as ReportableEnclaveResult};
use mc_transaction_core::{
    membership_proofs::compute_implied_merkle_root,
    ring_signature::KeyImage,
    tokens::Mob,
    tx::{Tx, TxOut, TxOutMembershipElement, TxOutMembershipProof},
    validation::TransactionValidationError,
    Amount, Block, BlockContents, BlockSignature, Token, TokenId,
};
use mc_util_from_random::FromRandom;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    convert::TryFrom,
    sync::{Arc, Mutex},
};

/// Domain separator for minted txouts public keys.
pub const MINTED_OUTPUT_PRIVATE_KEY_DOMAIN_TAG: &str = "mc_minted_output_private_key";

#[derive(Clone)]
pub struct ConsensusServiceMockEnclave {
    pub signing_keypair: Arc<Ed25519Pair>,
    pub blockchain_config: Arc<Mutex<BlockchainConfig>>,
}

impl Default for ConsensusServiceMockEnclave {
    fn default() -> Self {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let signing_keypair = Arc::new(Ed25519Pair::from_random(&mut csprng));
        let blockchain_config = Arc::new(Mutex::new(BlockchainConfig::default()));

        Self {
            signing_keypair,
            blockchain_config,
        }
    }
}

impl ConsensusServiceMockEnclave {
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

    /// Given a list of well formed encrypted txs + proofs and a root membership
    /// element, decrypt and validate "original" Tx transactions, and if
    /// successful return the list of transactions.
    fn get_txs_from_inputs(
        &self,
        well_formed_encrypted_txs_with_proofs: &[(
            WellFormedEncryptedTx,
            Vec<TxOutMembershipProof>,
        )],
        parent_block: &Block,
        root_element: &TxOutMembershipElement,
        config: &BlockchainConfig,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<Tx>> {
        if well_formed_encrypted_txs_with_proofs.is_empty() {
            return Ok(Vec::new());
        }

        let transactions_with_proofs: Vec<(Tx, Vec<TxOutMembershipProof>)> =
            well_formed_encrypted_txs_with_proofs
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

        for (tx, proofs) in transactions_with_proofs.iter() {
            mc_transaction_core::validation::validate(
                tx,
                parent_block.index + 1,
                config.block_version,
                proofs,
                Mob::MINIMUM_FEE,
                rng,
            )?;

            for proof in proofs {
                let root_element = compute_implied_merkle_root(proof)
                    .map_err(|_e| TransactionValidationError::InvalidLedgerContext)?;
                root_elements.push(root_element.clone());
            }
        }

        root_elements.sort();
        root_elements.dedup();

        if root_elements.len() != 1 {
            return Err(Error::InvalidLocalMembershipProof);
        }

        if root_element != &root_elements[0] {
            return Err(Error::InvalidLocalMembershipRootElement);
        }

        Ok(transactions_with_proofs
            .into_iter()
            .map(|(tx, _proofs)| tx)
            .collect())
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
        Ok(VerificationReport::default())
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
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let privkey = X25519EphemeralPrivate::from_random(&mut csprng);
        Ok((&privkey).into())
    }

    fn get_signer(&self) -> Result<Ed25519Public> {
        Ok(self.signing_keypair.public_key())
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
        let tx = mc_util_serial::decode(&locally_encrypted_tx.0)?;
        let well_formed_encrypted_tx = WellFormedEncryptedTx(locally_encrypted_tx.0);
        let well_formed_tx_context = WellFormedTxContext::from(&tx);

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
        let mut rng = McRng::default();
        let config = self.blockchain_config.lock().unwrap();

        // Get any "original" Tx transactions included in the inputs.
        let transactions = self.get_txs_from_inputs(
            &inputs.well_formed_encrypted_txs_with_proofs,
            parent_block,
            root_element,
            &config,
            &mut rng,
        )?;

        let mut key_images: Vec<KeyImage> = Vec::new();
        let mut outputs: Vec<TxOut> = Vec::new();
        for tx in transactions {
            key_images.extend(tx.key_images().into_iter());
            outputs.extend(tx.prefix.outputs.into_iter());
        }

        for mint_tx in &inputs.mint_txs {
            let recipient = PublicAddress::new(
                &mint_tx.prefix.spend_public_key,
                &mint_tx.prefix.view_public_key,
            );
            let output = TxOut::mint(
                &recipient,
                MINTED_OUTPUT_PRIVATE_KEY_DOMAIN_TAG.as_bytes(),
                parent_block,
                &inputs.mint_txs,
                Amount {
                    value: mint_tx.prefix.amount,
                    token_id: TokenId::from(mint_tx.prefix.token_id),
                },
            )
            .map_err(|e| Error::FormBlock(format!("AmountError: {:?}", e)))?;

            outputs.push(output);
        }

        let block_contents = BlockContents {
            key_images,
            outputs,
            mint_txs: inputs.mint_txs,
            mint_config_txs: inputs.mint_config_txs,
        };

        let block = Block::new_with_parent(
            config.block_version,
            parent_block,
            root_element,
            &block_contents,
        );

        let signature = BlockSignature::from_block_and_keypair(&block, &self.signing_keypair)?;

        Ok((block, block_contents, signature))
    }
}

// Get the marker trait as well
impl ConsensusEnclaveProxy for ConsensusServiceMockEnclave {}
