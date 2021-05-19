// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Mock enclave, used for tests

mod mock_consensus_enclave;

pub use mock_consensus_enclave::MockConsensusEnclave;

pub use mc_consensus_enclave_api::{
    ConsensusEnclave, ConsensusEnclaveProxy, Error, FeePublicKey, LocallyEncryptedTx, Result,
    SealedBlockSigningKey, TxContext, WellFormedEncryptedTx, WellFormedTxContext,
};

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
    constants::MINIMUM_FEE,
    membership_proofs::compute_implied_merkle_root,
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutMembershipProof},
    validation::TransactionValidationError,
    Block, BlockContents, BlockSignature, BLOCK_VERSION,
};
use mc_util_from_random::FromRandom;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;
use std::{
    convert::TryFrom,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

#[derive(Clone)]
pub struct ConsensusServiceMockEnclave {
    pub signing_keypair: Arc<Ed25519Pair>,
    pub minimum_fee: Arc<AtomicU64>,
}

impl Default for ConsensusServiceMockEnclave {
    fn default() -> Self {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let signing_keypair = Arc::new(Ed25519Pair::from_random(&mut csprng));

        Self {
            signing_keypair,
            minimum_fee: Arc::new(MINIMUM_FEE.into()),
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
        minimum_fee: Option<u64>,
    ) -> Result<(SealedBlockSigningKey, Vec<String>)> {
        self.minimum_fee
            .store(minimum_fee.unwrap_or(MINIMUM_FEE), Ordering::SeqCst);
        Ok((vec![], vec![]))
    }

    fn get_minimum_fee(&self) -> Result<u64> {
        Ok(self.minimum_fee.load(Ordering::SeqCst))
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
        encrypted_txs_with_proofs: &[(WellFormedEncryptedTx, Vec<TxOutMembershipProof>)],
    ) -> Result<(Block, BlockContents, BlockSignature)> {
        let transactions_with_proofs: Vec<(Tx, Vec<TxOutMembershipProof>)> =
            encrypted_txs_with_proofs
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
                proofs,
                MINIMUM_FEE,
                &mut rng,
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

        let mut key_images: Vec<KeyImage> = Vec::new();
        let mut outputs: Vec<TxOut> = Vec::new();
        for (tx, _proofs) in transactions_with_proofs {
            key_images.extend(tx.key_images().into_iter());
            outputs.extend(tx.prefix.outputs.into_iter());
        }

        let block_contents = BlockContents::new(key_images, outputs);

        let block = Block::new_with_parent(
            BLOCK_VERSION,
            &parent_block,
            &root_elements[0],
            &block_contents,
        );

        let signature = BlockSignature::from_block_and_keypair(&block, &self.signing_keypair)?;

        Ok((block, block_contents, signature))
    }
}

// Get the marker trait as well
impl ConsensusEnclaveProxy for ConsensusServiceMockEnclave {}
