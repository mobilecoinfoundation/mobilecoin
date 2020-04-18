// Copyright (c) 2018-2020 MobileCoin Inc.

//! Mock enclave, used for tests

pub use consensus_enclave_api::{
    ConsensusEnclave, ConsensusEnclaveProxy, Error, LocallyEncryptedTx, Result,
    SealedBlockSigningKey, TxContext, WellFormedEncryptedTx, WellFormedTxContext,
};

use attest::{IasNonce, Quote, QuoteNonce, Report, TargetInfo, VerificationReport};
use attest_enclave_api::{
    ClientAuthRequest, ClientAuthResponse, ClientSession, EnclaveMessage, PeerAuthRequest,
    PeerAuthResponse, PeerSession,
};
use common::ResponderId;
use keys::{Ed25519Pair, Ed25519Public, FromRandom, X25519EphemeralPrivate, X25519Public};
use mcrand::McRng;
use rand_core::SeedableRng;
use rand_hc::Hc128Rng;
use std::sync::Arc;
use transaction::{
    ring_signature::KeyImage,
    tx::{Tx, TxOutMembershipProof},
    Block, BlockSignature, RedactedTx, BLOCK_VERSION,
};

#[derive(Clone)]
pub struct ConsensusServiceMockEnclave {
    pub signing_keypair: Arc<Ed25519Pair>,
}

impl Default for ConsensusServiceMockEnclave {
    fn default() -> Self {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let signing_keypair = Arc::new(Ed25519Pair::from_random(&mut csprng));

        Self { signing_keypair }
    }
}

impl ConsensusServiceMockEnclave {
    pub fn tx_to_tx_context(tx: &Tx) -> TxContext {
        let locally_encrypted_tx = LocallyEncryptedTx(mcserial::encode(tx));
        let tx_hash = tx.tx_hash();
        let highest_indices = tx.get_membership_proof_highest_indices();
        let key_images: Vec<KeyImage> = tx.key_images();

        TxContext {
            locally_encrypted_tx,
            tx_hash,
            highest_indices,
            key_images,
        }
    }
}

impl ConsensusEnclave for ConsensusServiceMockEnclave {
    fn enclave_init(
        &self,
        _self_peer_id: &ResponderId,
        _self_client_id: &ResponderId,
        _sealed_key: &Option<SealedBlockSigningKey>,
    ) -> Result<SealedBlockSigningKey> {
        Ok(vec![])
    }

    fn get_identity(&self) -> Result<X25519Public> {
        let mut csprng = Hc128Rng::seed_from_u64(0);
        let privkey = X25519EphemeralPrivate::from_random(&mut csprng);
        Ok((&privkey).into())
    }

    fn get_signer(&self) -> Result<Ed25519Public> {
        Ok(self.signing_keypair.public_key())
    }

    fn new_ereport(&self, _qe_info: TargetInfo) -> Result<(Report, QuoteNonce)> {
        Ok((Report::default(), QuoteNonce::default()))
    }

    fn verify_quote(&self, _quote: Quote, _qe_report: Report) -> Result<IasNonce> {
        Ok(IasNonce::default())
    }

    fn verify_ias_report(&self, _ias_report: VerificationReport) -> Result<()> {
        Ok(())
    }

    fn get_ias_report(&self) -> Result<VerificationReport> {
        Ok(VerificationReport::default())
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

    fn peer_connect(&self, _node_id: &ResponderId, _msg: PeerAuthResponse) -> Result<PeerSession> {
        Ok(vec![].into())
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
        let tx = mcserial::decode(&locally_encrypted_tx.0)?;
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
    ) -> Result<(Block, Vec<RedactedTx>, BlockSignature)> {
        let transactions_with_proofs: Vec<(Tx, Vec<TxOutMembershipProof>)> =
            encrypted_txs_with_proofs
                .iter()
                .map(|(encrypted_tx, proofs)| {
                    // These bytes are normally an enclave-encrypted Tx, but here, it is just serialized.
                    let ciphertext = &encrypted_tx.0;
                    let tx = mcserial::decode::<Tx>(ciphertext).unwrap();
                    (tx, proofs.clone())
                })
                .collect();

        // root_elements contains the root hash of the Merkle tree of all TxOuts in the ledger
        // that were used to validate the tranasctions.
        let mut root_elements = Vec::new();
        let mut rng = McRng::default();

        for (tx, proofs) in transactions_with_proofs.iter() {
            transaction::validation::validate(tx, parent_block.index + 1, proofs, &mut rng)?;

            for proof in proofs {
                let root_element = proof
                    .elements
                    .last() // The last element contains the root hash.
                    .ok_or(Error::InvalidLocalMembershipProof)?;
                root_elements.push(root_element.clone());
            }
        }

        root_elements.sort();
        root_elements.dedup();

        if root_elements.len() != 1 {
            return Err(Error::InvalidLocalMembershipProof);
        }

        let redacted_transactions: Vec<_> = transactions_with_proofs
            .into_iter()
            .map(|(tx, _proofs)| tx.redact())
            .collect();

        let block = Block::new(
            BLOCK_VERSION,
            &parent_block.id,
            parent_block.index + 1,
            parent_block.cumulative_txo_count + redacted_transactions.len() as u64,
            &root_elements[0],
            &redacted_transactions,
        );

        let signature = BlockSignature::from_block_and_keypair(&block, &self.signing_keypair)?;

        Ok((block, redacted_transactions, signature))
    }
}

// Get the marker trait as well
impl ConsensusEnclaveProxy for ConsensusServiceMockEnclave {}
