// Copyright (c) 2018-2021 The MobileCoin Foundation

//! MobileCoin Client Object

use crate::{
    cached_tx_data::{CachedTxData, OwnedTxOut},
    error::{Error, Result},
    MemoHandlerError, TransactionStatus,
};
use core::{convert::TryFrom, result::Result as StdResult, str::FromStr};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_core::Verifier;
use mc_common::{
    logger::{log, Logger},
    HashSet,
};
use mc_connection::{
    BlockchainConnection, Connection, HardcodedCredentialsProvider, ThickClient, UserTxConnection,
};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_fog_api::ledger::TxOutResultCode;
use mc_fog_ledger_connection::{
    FogKeyImageGrpcClient, FogMerkleProofGrpcClient, FogUntrustedLedgerGrpcClient,
    OutputResultExtension,
};
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_report_validation::{FogPubkeyResolver, FogResolver};
use mc_fog_types::BlockCount;
use mc_fog_view_connection::FogViewGrpcClient;
use mc_transaction_core::{
    constants::MINIMUM_FEE,
    onetime_keys::*,
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutMembershipProof},
    BlockIndex,
};
use mc_transaction_std::{
    ChangeDestination, InputCredentials, MemoType, RTHMemoBuilder, SenderMemoCredential,
    TransactionBuilder,
};
use mc_util_uri::{ConnectionUri, FogUri};
use rand::Rng;

/// Default number of blocks used for calculating transaction tombstone block
/// number. See `new_tx_block_attempts` below.
const DEFAULT_NEW_TX_BLOCK_ATTEMPTS: u16 = 50;

/// Represents the entire sample paykit object, capable of balance checks and
/// sending transactions
pub struct Client {
    consensus_service_conn: ThickClient<HardcodedCredentialsProvider>,
    fog_view: FogViewGrpcClient,
    fog_merkle_proof: FogMerkleProofGrpcClient,
    fog_key_image: FogKeyImageGrpcClient,
    fog_report_conn: GrpcFogReportConnection,
    fog_verifier: Verifier,
    fog_untrusted: FogUntrustedLedgerGrpcClient,
    ring_size: usize,
    account_key: AccountKey,
    tx_data: CachedTxData,

    /// Number of blocks for which to try and get the new transaction to be
    /// included in the ledger. This value is used to calculate the
    /// tombstone block when generating a new transaction.
    new_tx_block_attempts: u16,

    logger: Logger,
}

impl Client {
    /// Create a new sample paykit object
    pub fn new(
        consensus_service_conn: ThickClient<HardcodedCredentialsProvider>,
        fog_view: FogViewGrpcClient,
        fog_merkle_proof: FogMerkleProofGrpcClient,
        fog_key_image: FogKeyImageGrpcClient,
        fog_report_conn: GrpcFogReportConnection,
        fog_verifier: Verifier,
        fog_untrusted: FogUntrustedLedgerGrpcClient,
        ring_size: usize,
        account_key: AccountKey,
        address_book: Vec<PublicAddress>,
        logger: Logger,
    ) -> Self {
        let tx_data = CachedTxData::new(address_book, logger.clone());

        Client {
            consensus_service_conn,
            fog_view,
            fog_merkle_proof,
            fog_key_image,
            fog_report_conn,
            fog_verifier,
            fog_untrusted,
            ring_size,
            account_key,
            tx_data,
            new_tx_block_attempts: DEFAULT_NEW_TX_BLOCK_ATTEMPTS,
            logger,
        }
    }

    /// Get the account key associated to this paykit
    pub fn get_account_key(&self) -> &AccountKey {
        &self.account_key
    }

    /// Get the host:port we're connected to.
    pub fn consensus_service_address(&self) -> String {
        self.consensus_service_conn.uri().addr()
    }

    /// This allows to set the tombstone block limit for newly-created
    /// transactions.
    ///
    /// The tombstone block value is a number attached to a submitted
    /// transaction, after which it should fail if it has not been processed
    /// yet. This sets how many blocks after the current block we should
    /// wait. Since current block is an approximate notion, this should not
    /// be too small. If it is too large then it will take a long time to
    /// determine if a transaction was successful.
    pub fn set_new_tx_block_attempts(&mut self, new_tx_block_attempts: u16) {
        self.new_tx_block_attempts = new_tx_block_attempts;
    }

    /// Check this user's current available balance.
    ///
    /// Returns:
    /// * Balance (in picomob)
    /// * Number of blocks in the chain at the time that this was the correct
    ///   balance
    pub fn check_balance(&mut self) -> Result<(u64, BlockCount)> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_balance");
        self.tx_data.poll_fog(
            &mut self.fog_view,
            &mut self.fog_key_image,
            &self.account_key,
        )?;
        Ok(self.compute_balance())
    }

    /// Compute the balance based on locally available data.
    /// Does NOT make any new network calls.
    ///
    /// Returns:
    /// * Balance (in picomob)
    /// * Number of blocks in the chain at the time that this was the correct
    ///   balance
    pub fn compute_balance(&mut self) -> (u64, BlockCount) {
        self.tx_data.get_balance()
    }

    /// Get balance debug print message
    pub fn debug_balance(&mut self) -> String {
        self.tx_data.debug_balance()
    }

    /// Get the last memo (or validation error) that we recieved from a TxOut
    pub fn get_last_memo(&mut self) -> &StdResult<Option<MemoType>, MemoHandlerError> {
        self.tx_data.get_last_memo()
    }

    /// Submits a transaction to the MobileCoin network.
    ///
    /// To get a transaction, call build_transaction.
    ///
    /// This should usually be followed by doing a polling loop on
    /// "is_transaction_accepted". Then, perform another balance check to
    /// get refreshed key image data before attempting to create another
    /// transaction.
    pub fn send_transaction(&mut self, transaction: &Tx) -> Result<()> {
        self.consensus_service_conn.propose_tx(transaction)?;
        Ok(())
    }

    /// Check if a transaction has appeared in the ledger, by checking if one of
    /// its output TxOut's did. Returns either Appeared (one of the outputs
    /// appeared), Expired (tombstone block has passed), or Unknown (neither).
    ///
    /// Typically this is called in a polling loop to determine if a submitted
    /// transaction settled successfully.
    ///
    /// Arguments:
    /// * Transaction to check for. Must have at least one output TxOut.
    ///
    /// Returns:
    /// * A transaction status for the transaction: its output tx out appeared
    ///   (in a particular block), it expired, or neither has happened yet
    /// * Error if there is a network error or error response from server
    ///
    /// Note: If the call returns Appeared(block_count), then the transaction
    /// appeared in block_count.
    pub fn is_transaction_present(&mut self, transaction: &Tx) -> Result<TransactionStatus> {
        assert!(
            !transaction.prefix.outputs.is_empty(),
            "Transaction must have at least one output"
        );
        let public_key = transaction.prefix.outputs[0].public_key;

        match self.fog_untrusted.get_tx_outs(vec![public_key]) {
            Ok(result) => {
                for tx_out_result in result.results.into_iter() {
                    if let Some(external_compressed_ristretto) =
                        tx_out_result.tx_out_pubkey.as_ref()
                    {
                        if let Ok(this_pubkey) =
                            CompressedRistrettoPublic::try_from(external_compressed_ristretto)
                        {
                            if this_pubkey == public_key {
                                const NOT_FOUND: u32 = TxOutResultCode::NotFound as u32;
                                const FOUND: u32 = TxOutResultCode::Found as u32;
                                const MALFORMED_REQUEST: u32 =
                                    TxOutResultCode::MalformedRequest as u32;
                                const DATABASE_ERROR: u32 = TxOutResultCode::DatabaseError as u32;

                                match tx_out_result.result_code as u32 {
                                    FOUND => {
                                        return Ok(TransactionStatus::Appeared(
                                            tx_out_result.block_index,
                                        ));
                                    }
                                    MALFORMED_REQUEST => {
                                        panic!(
                                            "Server reported our request {:?} was malformed",
                                            public_key
                                        );
                                    }
                                    DATABASE_ERROR => {
                                        return Ok(TransactionStatus::Unknown);
                                    }
                                    NOT_FOUND => {
                                        // Note: A transaction must appear BEFORE the
                                        // tombstone_block,
                                        // it cannot appear in the tombstone block.
                                        if result.num_blocks >= transaction.prefix.tombstone_block {
                                            return Ok(TransactionStatus::Expired);
                                        } else {
                                            return Ok(TransactionStatus::Unknown);
                                        }
                                    }
                                    other => {
                                        panic!("Server returned an unknown status code: {}", other);
                                    }
                                };
                            }
                        } else {
                            log::error!(
                                self.logger,
                                "Invalid compressed ristretto returned from server: {:?}",
                                tx_out_result.tx_out_pubkey
                            );
                        }
                    } else {
                        log::error!(
                            self.logger,
                            "Missing required field from server: tx_out_pubkey"
                        );
                    }
                }
                panic!("Did not find queried public key among the server responses, this is a server bug");
            }
            Err(e) => Err(Error::UntrustedTxOut(e)),
        }
    }

    /// Builds a transaction that transfers `amount` from this account to
    /// `target_address`, returning any "change" to ourself.
    ///
    /// This reaches out to the fog merkle proof server to get merkle proofs for
    /// the inputs and mixins. It also reaches out to the report server to
    /// get the current fog public key, if anyone here has fog.
    ///
    /// # Arguments
    /// * `amount` - The amount that will be sent, not including the transaction
    ///   fee.
    /// * `target_address` - the recipient's address.
    /// * `rng` - Randomness.
    /// * `fee` - The transaction fee to use
    pub fn build_transaction<T: RngCore + CryptoRng>(
        &mut self,
        amount: u64,
        target_address: &PublicAddress,
        rng: &mut T,
        fee: u64,
    ) -> Result<Tx> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.build_transaction");

        log::debug!(
            self.logger,
            "Building transaction for amount {:?} from source address {:?} to target address {:?}",
            amount,
            self.account_key.default_subaddress(),
            target_address
        );

        // Arbitrarily choose 3 as the maximum number of inputs
        // TODO: Should be based on fee scaling and fee choice
        const TARGET_NUM_INPUTS: usize = 3;
        let inputs = self
            .tx_data
            .get_transaction_inputs(amount + MINIMUM_FEE, TARGET_NUM_INPUTS)?;
        let inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = self.get_proofs(&inputs)?;
        let rings: Vec<Vec<(TxOut, TxOutMembershipProof)>> = self.get_rings(inputs.len(), rng)?;

        let tombstone_block = self.compute_tombstone_block()?;

        // Make fog resolver
        // TODO: This should be the change subaddress, not the default subaddress, for
        // self.account_key
        let fog_uris = (&[&self.account_key.default_subaddress(), target_address])
            .iter()
            .filter_map(|addr| addr.fog_report_url())
            .map(FogUri::from_str)
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let fog_responses = self
            .fog_report_conn
            .fetch_fog_reports(fog_uris.into_iter())?;
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_verifier)?;

        build_transaction_helper(
            inputs,
            rings,
            amount,
            &self.account_key.clone(),
            target_address,
            tombstone_block,
            fog_resolver,
            rng,
            &self.logger,
            fee,
        )
    }

    /// Helper: Get merkle proofs corresponding to a given set of our inputs
    ///
    /// This is needed when building transactions.
    ///
    /// # Arguments
    /// * inputs: The OwnedTxOut records to get proofs for
    ///
    /// Returns
    /// * A sequence of OwnedTxOut records with corresponding proofs of
    ///   membership
    ///
    /// Note: The TxOut object returned by this function is the TxOut returned
    /// from from ledger, not the one passed in. This is because the TxOut's
    /// from fog view won't have the hint field, to save storage space.
    /// Submitting those TxOuts to consensus will cause the transaction to be
    /// rejected, because the merkle proof check will fail.
    fn get_proofs(
        &mut self,
        inputs: &[OwnedTxOut],
    ) -> Result<Vec<(OwnedTxOut, TxOutMembershipProof)>> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_proofs");

        // Use the indices from the new TXOs to get corresponding merkle proofs of
        // membership
        let indices: Vec<u64> = inputs.iter().map(|input| input.global_index).collect();

        // FIXME: We are not sure whether this is a necessary parameter under ORAM.
        let merkle_root_block: u64 = 0;

        log::debug!(
            self.logger,
            "Sending LedgerConnection:GetOutputs {:?}",
            indices
        );
        let outputs_and_proofs: Vec<(TxOut, TxOutMembershipProof)> = self
            .fog_merkle_proof
            .get_outputs(indices.clone(), merkle_root_block)?
            .results
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, result)| {
                if result.index != indices[idx] {
                    panic!("unhandled: Server returned indices in an unexpected order");
                }
                match result.status() {
                    Err(err) => panic!(
                        "unhandled: Server failed to compute a merkle proof: {}",
                        err
                    ),
                    Ok(None) => panic!("unhandled: Server did not find one of the outputs we need"),
                    Ok(Some(res)) => res,
                }
            })
            .collect();

        log::info!(self.logger, "Retrieved {} TXOs", outputs_and_proofs.len());

        // This is where we replace the TxOut object with the one we got from fog ledger
        Ok(outputs_and_proofs
            .into_iter()
            .zip(inputs.iter().cloned())
            .map(|((tx_out, proof), owned_tx_out)| {
                let mut owned_tx_out_result = owned_tx_out;
                owned_tx_out_result.tx_out = tx_out;
                (owned_tx_out_result, proof)
            })
            .collect())
    }

    /// Gets several rings' worth of mixin TxOuts, with proofs of membership.
    ///
    /// TODO: In discussions, some think the mixin distribution should
    /// eventually be made "relatively close" to the global index of the
    /// true input, but that is not implemented yet.
    ///
    /// # Arguments
    /// *`num_rings` - The number of rings of TxOuts to request.
    ///
    /// # Returns
    /// Returns a collection of "rings", where each "ring" contains
    /// self.ring_size elements.
    fn get_rings<T: RngCore + CryptoRng>(
        &mut self,
        num_rings: usize,
        rng: &mut T,
    ) -> Result<Vec<Vec<(TxOut, TxOutMembershipProof)>>> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_rings");

        let num_requested = num_rings * self.ring_size;
        let sample_limit = self.tx_data.get_global_txo_count() as usize;

        // Randomly sample `num_requested` TxOuts, without replacement.
        if sample_limit < num_requested {
            return Err(Error::InsufficientTxOutsInBlockchain(
                sample_limit,
                num_requested,
            ));
        }

        let mut sampled_indices: HashSet<u64> = HashSet::default();
        while sampled_indices.len() < num_requested {
            let index = rng.gen_range(0..sample_limit);
            sampled_indices.insert(index as u64);
        }
        let indices: Vec<u64> = sampled_indices.iter().cloned().collect();
        // FIXME: We are not sure whether this is a necessary parameter under ORAM.
        let merkle_root_block: u64 = 0; // self.get_txo_cursor(); // cursor > 0 ? cursor - 1 : 0

        let outputs_and_proofs: Vec<(TxOut, TxOutMembershipProof)> = self
            .fog_merkle_proof
            .get_outputs(indices.clone(), merkle_root_block)?
            .results
            .iter()
            .enumerate()
            .map(|(idx, result)| {
                if result.index != indices[idx] {
                    panic!("unhandled: Server returned indices in an unexpected order");
                }
                match result.status() {
                    Err(err) => panic!(
                        "unhandled: Server failed to computer a merkle proof: {}",
                        err
                    ),
                    Ok(None) => panic!("unhandled: Server did not find one of the outputs we need"),
                    Ok(Some(res)) => res,
                }
            })
            .collect();

        // FIXME: reserve? iter tricks?
        let mut rings_with_proofs: Vec<Vec<(TxOut, TxOutMembershipProof)>> = Vec::new();
        let mut ring: Vec<(TxOut, TxOutMembershipProof)> = Vec::new();
        for txo_and_proof in outputs_and_proofs.iter() {
            ring.push(txo_and_proof.clone());
            if ring.len() == self.ring_size {
                rings_with_proofs.push(ring);
                ring = Vec::new();
            }
        }

        log::info!(self.logger, "Retrieved {:?} rings", rings_with_proofs.len());
        Ok(rings_with_proofs)
    }

    /// Gets the approximate number of blocks in the ledger and adds
    /// self.new_tx_block_attempts value, to compute an appropriate
    /// tombstone block value
    fn compute_tombstone_block(&mut self) -> Result<BlockIndex> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_num_blocks");
        // Use the key images endpoint with an empty vec
        let res = self.fog_key_image.check_key_images(&Vec::new())?;
        log::info!(
            self.logger,
            "Number of blocks in ledger: {}",
            res.num_blocks
        );
        Ok(res.num_blocks + self.new_tx_block_attempts as u64)
    }

    /// Retrieve the currently configured minimum fee from the consensus service
    pub fn get_fee(&mut self) -> Result<u64> {
        Ok(self.consensus_service_conn.fetch_block_info()?.minimum_fee)
    }
}

/// Builds a transaction that spends `inputs`, sends `amount` to the recipient,
/// and returns the remainder to the sender minus the transaction fee.
///
/// # Arguments
/// * `inputs` - Inputs that will be spent by the transaction.
/// * `rings` - A ring of TxOuts and membership proofs for each input.
/// * `amount` - The amount that will be sent.
/// * `source_account_key` - The sender's account key.
/// * `source_acct_server_pubkey` - The sender's account server key, if any.
/// * `target_address` - The recipient's public key.
/// * `target_acct_server_pubkey` - The recipient's account server key, if any.
/// * `tombstone_block` - The block index after which this transaction is no
///   longer valid.
/// * `rng` -
fn build_transaction_helper<T: RngCore + CryptoRng, FPR: FogPubkeyResolver>(
    inputs: Vec<(OwnedTxOut, TxOutMembershipProof)>,
    rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
    amount: u64,
    source_account_key: &AccountKey,
    target_address: &PublicAddress,
    tombstone_block: BlockIndex,
    fog_resolver: FPR,
    rng: &mut T,
    logger: &Logger,
    fee: u64,
) -> Result<Tx> {
    if rings.len() != inputs.len() {
        log::error!(
            logger,
            "{:?} rings but {:?} inputs.",
            rings.len(),
            inputs.len()
        );
        return Err(Error::RingsForInput(rings.len(), inputs.len()));
    }

    let mut memo_builder = RTHMemoBuilder::default();
    memo_builder.set_sender_credential(SenderMemoCredential::from(source_account_key));
    memo_builder.enable_destination_memo();

    let mut tx_builder = TransactionBuilder::new(fog_resolver, memo_builder);
    tx_builder.set_fee(fee)?;

    let input_amount = inputs.iter().fold(0, |acc, (txo, _)| acc + txo.value);
    let fee = tx_builder.get_fee();
    if (amount + fee) > input_amount {
        return Err(Error::InsufficientFunds);
    }
    let change = input_amount - (amount + fee);

    // Unzip each vec of tuples into a tuple of vecs.
    let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
        .into_iter()
        .map(|tuples| tuples.into_iter().unzip())
        .collect();

    for (input_txo, input_proof) in inputs {
        let (mut ring, mut membership_proofs) = rings_and_proofs
            .pop()
            .expect("Consistency failure converting vec of tuple into tuple of vecs");
        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        // Add the input to the ring.
        let position_opt = ring.iter().position(|tx_out| *tx_out == input_txo.tx_out);
        let real_key_index = match position_opt {
            Some(position) => {
                // The input is already present in the ring.
                // This could happen if ring elements are sampled randomly from the ledger.
                position
            }
            None => {
                // The input is not already in the ring.
                if ring.is_empty() {
                    // Append the input and its proof of membership.
                    ring.push(input_txo.tx_out.clone());
                    membership_proofs.push(input_proof.clone());
                } else {
                    // Replace the first element of the ring.
                    ring[0] = input_txo.tx_out.clone();
                    membership_proofs[0] = input_proof.clone();
                }
                // The real input is always the first element. This is safe because
                // TransactionBuilder sorts each ring.
                0
            }
        };

        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        let onetime_private_key = recover_onetime_private_key(
            &RistrettoPublic::try_from(&input_txo.tx_out.public_key)?,
            source_account_key.view_private_key(),
            &source_account_key.default_subaddress_spend_private(),
        );

        let key_image = KeyImage::from(&onetime_private_key);
        log::trace!(
            logger,
            "Adding input: ring {:?}, utxo index {:?}, key image {:?}, pubkey {:?}",
            ring,
            real_key_index,
            key_image,
            input_txo.tx_out.public_key
        );

        let ring_len = ring.len();
        tx_builder.add_input(
            InputCredentials::new(
                ring,
                membership_proofs,
                real_key_index,
                onetime_private_key,
                *source_account_key.view_private_key(),
            )
            .or(Err(Error::BrokenRing(ring_len, real_key_index)))?,
        );
    }

    // Resolve account server key if the receiver specifies an account service in
    // their public address
    tx_builder
        .add_output(amount, target_address, rng)
        .map_err(Error::AddOutput)?;

    let change_destination = ChangeDestination::from(source_account_key);

    tx_builder
        .add_change_output(change, &change_destination, rng)
        .map_err(|err| {
            log::error!(logger, "Could not add change due to {:?}", err);
            Error::AddOutput(err)
        })?;

    tx_builder.set_tombstone_block(tombstone_block);

    Ok(tx_builder.build(rng)?)
}

#[cfg(test)]
mod test_build_transaction_helper {
    use super::*;
    use core::result::Result as StdResult;
    use mc_account_keys::{AccountKey, PublicAddress};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_fog_report_validation::{FogPubkeyError, FullyValidatedFogPubkey};
    use mc_fog_types::view::{FogTxOut, FogTxOutMetadata, TxOutRecord};
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB,
        tx::{TxOut, TxOutMembershipProof},
    };
    use mc_transaction_core_test_utils::get_outputs;
    use rand::{rngs::StdRng, SeedableRng};

    // Mock of FogPubkeyResolver
    struct FakeAcctResolver {}
    impl FogPubkeyResolver for FakeAcctResolver {
        fn get_fog_pubkey(
            &self,
            _addr: &PublicAddress,
        ) -> StdResult<FullyValidatedFogPubkey, FogPubkeyError> {
            unimplemented!()
        }
    }

    // `build_transaction_helper` should return a Tx when `rings` contains TxOuts
    // that do not appear in `inputs`.
    #[test_with_logger]
    fn test_build_transaction_helper_rings_disjoint_from_inputs(logger: Logger) {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);

        let sender_account_key = AccountKey::random(&mut rng);
        let sender_public_address = sender_account_key.default_subaddress();

        // Amount per input.
        let initial_amount = 300 * MILLIMOB_TO_PICOMOB;
        let amount_to_send = 457 * MILLIMOB_TO_PICOMOB;
        let num_inputs = 3;
        let ring_size = 1;

        // Create inputs.
        let inputs = {
            let mut recipient_and_amount: Vec<(PublicAddress, u64)> = Vec::new();
            for _i in 0..num_inputs {
                recipient_and_amount.push((sender_public_address.clone(), initial_amount));
            }
            let outputs = get_outputs(&recipient_and_amount, &mut rng);

            let cached_inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = outputs
                .into_iter()
                .map(|tx_out| {
                    let fog_tx_out = FogTxOut::from(&tx_out);
                    let meta = FogTxOutMetadata::default();
                    let txo_record = TxOutRecord::new(fog_tx_out, meta);

                    let owned_tx_out = OwnedTxOut::new(txo_record, &sender_account_key).unwrap();

                    let proof = TxOutMembershipProof::new(0, 0, Default::default());

                    (owned_tx_out, proof)
                })
                .collect();

            cached_inputs
        };

        assert_eq!(inputs.len(), num_inputs);

        // Create rings.
        let mut rings: Vec<Vec<TxOut>> = Vec::new();
        for _i in 0..num_inputs {
            let ring: Vec<TxOut> = {
                let mut recipient_and_amount: Vec<(PublicAddress, u64)> = Vec::new();
                for _i in 0..ring_size {
                    recipient_and_amount.push((sender_public_address.clone(), 33));
                }
                get_outputs(&recipient_and_amount, &mut rng)
            };
            assert_eq!(ring.len(), ring_size);
            rings.push(ring);
        }

        assert_eq!(inputs.len(), rings.len());

        let mut rings_and_membership_proofs: Vec<Vec<(TxOut, TxOutMembershipProof)>> = Vec::new();
        for ring in rings.into_iter() {
            let ring_with_proofs = ring
                .into_iter()
                .map(|tx_out| {
                    let membership_proof = TxOutMembershipProof::new(0, 0, Default::default());
                    (tx_out, membership_proof)
                })
                .collect();
            rings_and_membership_proofs.push(ring_with_proofs);
        }

        let recipient_account_key = AccountKey::random(&mut rng);

        let fake_acct_resolver = FakeAcctResolver {};
        let tx = build_transaction_helper(
            inputs,
            rings_and_membership_proofs,
            amount_to_send,
            &sender_account_key,
            &recipient_account_key.default_subaddress(),
            super::BlockIndex::max_value(),
            fake_acct_resolver,
            &mut rng,
            &logger,
            MINIMUM_FEE,
        )
        .unwrap();

        // The transaction should contain the correct number of inputs.
        assert_eq!(tx.prefix.inputs.len(), num_inputs);

        // Each TxIn should contain a ring of `ring_size` elements. If `ring_size` is
        // zero, the ring will have size 1 after the input is included.
        for tx_in in tx.prefix.inputs {
            assert_eq!(tx_in.ring.len(), ring_size);
        }

        // TODO: `tx` should contain the correct number of outputs.

        // TODO: `tx` should send the correct amount to the recipient.

        // TODO: `tx` should return the correct "change" to the sender.
    }

    #[test]
    #[ignore]
    // `build_transaction_helper` should return a Tx when `rings` contains an input.
    fn test_build_transaction_helper_rings_intersect_inputs() {
        unimplemented!()
    }

    // TODO: error conditions for builder_transaction_helper
}
