// Copyright (c) 2018-2022 The MobileCoin Foundation

//! MobileCoin Client Object

use crate::{
    cached_tx_data::{CachedTxData, OwnedTxOut},
    error::{Error, Result},
    BlockInfo, MemoHandlerError, TransactionStatus,
};
use core::{result::Result as StdResult, str::FromStr};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_verifier::Verifier;
use mc_blockchain_types::{BlockIndex, BlockVersion};
use mc_common::logger::{log, Logger};
use mc_connection::{
    BlockchainConnection, Connection, HardcodedCredentialsProvider, ThickClient, UserTxConnection,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_crypto_ring_signature_signer::{LocalRingSigner, OneTimeKeyDeriveData, RingSigner};
use mc_fog_api::ledger::TxOutResultCode;
use mc_fog_ledger_connection::{
    FogBlockGrpcClient, FogKeyImageGrpcClient, FogMerkleProofGrpcClient,
    FogUntrustedLedgerGrpcClient, OutputResultExtension,
};
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_report_resolver::FogResolver;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_fog_types::{ledger::KeyImageResultCode, BlockCount};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_transaction_core::{
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, SignedContingentInput, TokenId,
};
use mc_transaction_std::{
    EmptyMemoBuilder, InputCredentials, MemoType, RTHMemoBuilder, ReservedSubaddresses,
    SenderMemoCredential, SignedContingentInputBuilder, TransactionBuilder,
};
use mc_util_telemetry::{block_span_builder, telemetry_static_key, tracer, Key, Span};
use mc_util_uri::{ConnectionUri, FogUri};
use rand::Rng;
use std::collections::{HashMap, HashSet};

/// Default number of blocks used for calculating transaction tombstone block
/// number. See `new_tx_block_attempts` below.
const DEFAULT_NEW_TX_BLOCK_ATTEMPTS: u16 = 50;

/// Telemetry: block index the transaction is expected to land at.
const TELEMETRY_BLOCK_INDEX_KEY: Key = telemetry_static_key!("block-index");

/// Represents the entire sample paykit object, capable of balance checks and
/// sending transactions
pub struct Client {
    consensus_service_conn: ThickClient<HardcodedCredentialsProvider>,
    fog_view: FogViewGrpcClient,
    fog_merkle_proof: FogMerkleProofGrpcClient,
    fog_key_image: FogKeyImageGrpcClient,
    fog_block: FogBlockGrpcClient,
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
        fog_block: FogBlockGrpcClient,
        fog_report_conn: GrpcFogReportConnection,
        fog_verifier: Verifier,
        fog_untrusted: FogUntrustedLedgerGrpcClient,
        ring_size: usize,
        account_key: AccountKey,
        address_book: Vec<PublicAddress>,
        logger: Logger,
    ) -> Self {
        let tx_data = CachedTxData::new(account_key.clone(), address_book, logger.clone());

        Client {
            consensus_service_conn,
            fog_view,
            fog_merkle_proof,
            fog_key_image,
            fog_block,
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
    /// * Balances (for all token types) (in picomob)
    /// * Number of blocks in the chain at the time that this was the correct
    ///   balance
    pub fn check_balance(&mut self) -> Result<(HashMap<TokenId, u64>, BlockCount)> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_balance");
        self.tx_data.poll_fog(
            &mut self.fog_view,
            &mut self.fog_key_image,
            &mut self.fog_block,
        )?;
        Ok(self.compute_balance())
    }

    /// Compute the balance based on locally available data.
    /// Does NOT make any new network calls.
    ///
    /// Returns:
    /// * HashMap<TokenId, u64> Balance (in picomob or equivalent for each
    ///   token)
    /// * Number of blocks in the chain at the time that this was the correct
    ///   balance
    pub fn compute_balance(&self) -> (HashMap<TokenId, u64>, BlockCount) {
        self.tx_data.get_balance()
    }

    /// Get balance debug print message
    pub fn debug_balance(&mut self) -> String {
        self.tx_data.debug_balance()
    }

    /// Get the last memo (or validation error) that we recieved from a TxOut
    pub fn get_last_memo(&self) -> &StdResult<Option<MemoType>, MemoHandlerError> {
        self.tx_data.get_last_memo()
    }

    /// Get the latest block version that we heard about from fog
    /// Note that this may not be a "valid" block version if our software is old
    pub fn get_latest_block_version(&self) -> u32 {
        self.tx_data.get_latest_block_version()
    }

    /// Submits a transaction to the MobileCoin network.
    ///
    /// To get a transaction, call build_transaction.
    ///
    /// This should usually be followed by doing a polling loop on
    /// "is_transaction_accepted". Then, perform another balance check to
    /// get refreshed key image data before attempting to create another
    /// transaction.
    pub fn send_transaction(&mut self, transaction: &Tx) -> Result<u64> {
        let start_time = std::time::SystemTime::now();
        let block_count = self.consensus_service_conn.propose_tx(transaction)?;

        let tracer = tracer!();
        let mut span = block_span_builder(&tracer, "send_transaction", block_count)
            .with_start_time(start_time)
            .start(&tracer);

        span.set_attribute(TELEMETRY_BLOCK_INDEX_KEY.i64(block_count as i64));
        span.end();

        Ok(block_count)
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
        amount: Amount,
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

        let required_input_amount = {
            let mut amount = amount;
            amount.value += fee;
            amount
        };

        // Arbitrarily choose 3 as the maximum number of inputs
        // TODO: Should be based on fee scaling and fee choice
        const TARGET_NUM_INPUTS: usize = 3;
        let inputs = self
            .tx_data
            .get_transaction_inputs(required_input_amount, TARGET_NUM_INPUTS)?;
        let inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = self.get_proofs(&inputs)?;
        let rings: Vec<Vec<(TxOut, TxOutMembershipProof)>> = self.get_rings(&inputs, rng)?;

        let tombstone_block = self.compute_tombstone_block()?;

        let block_version = BlockVersion::try_from(self.tx_data.get_latest_block_version())?;

        // Make fog resolver
        let fog_uris = (&[&self.account_key.change_subaddress(), target_address])
            .iter()
            .filter_map(|addr| addr.fog_report_url())
            .map(FogUri::from_str)
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let fog_responses = self
            .fog_report_conn
            .fetch_fog_reports(fog_uris.into_iter())?;
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_verifier)?;

        let ring_signer = LocalRingSigner::from(&self.account_key);

        build_transaction_helper(
            block_version,
            inputs,
            rings,
            amount,
            &self.account_key.clone(),
            target_address,
            tombstone_block,
            fog_resolver,
            &ring_signer,
            rng,
            &self.logger,
            fee,
        )
    }

    /// Builds a signed contingent input that offers to trade "this" amount
    /// for "that" amount.
    ///
    /// # Arguments
    /// * `offered` - The amount that we are offering
    /// * `requested` - The amount that we want in return
    /// * `rng` - Randomness.
    pub fn build_swap_proposal<T: RngCore + CryptoRng>(
        &mut self,
        offered: Amount,
        requested: Amount,
        allow_partial_fill: bool,
        rng: &mut T,
    ) -> Result<SignedContingentInput> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.build_swap_proposal");

        // Only one input can be used, otherwise defragmentation is required
        let inputs = self.tx_data.get_transaction_inputs(offered, 1)?;
        let inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = self.get_proofs(&inputs)?;
        let rings: Vec<Vec<(TxOut, TxOutMembershipProof)>> = self.get_rings(&inputs, rng)?;

        assert_eq!(inputs.len(), 1);
        assert_eq!(rings.len(), 1);

        let (input, input_proof) = (&inputs[0]).clone();
        let ring = (&rings[0]).clone();

        // Check amount found, calculate change
        let input_amount = input.amount;
        assert!(
            offered.token_id == input_amount.token_id,
            "get_transaction_inputs post condition failed"
        );
        assert!(
            offered.value <= input_amount.value,
            "get_transaction_inputs post condition failed"
        );
        let change = Amount::new(input_amount.value - offered.value, offered.token_id);

        let tombstone_block = self.compute_tombstone_block()?;

        let block_version = BlockVersion::try_from(self.tx_data.get_latest_block_version())?;

        // Make fog resolver
        let fog_uris = self
            .account_key
            .fog_report_url()
            .map(FogUri::from_str)
            .transpose()?;
        let fog_responses = self
            .fog_report_conn
            .fetch_fog_reports(fog_uris.into_iter())?;
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_verifier)?;

        let (ring, membership_proofs): (Vec<TxOut>, Vec<TxOutMembershipProof>) =
            ring.into_iter().unzip();
        let input_credentials = input_credentials_helper(
            input,
            input_proof,
            ring,
            membership_proofs,
            &self.account_key,
        )?;

        // TODO: Use the RTHMemoBuilder?
        let mut sci_builder = SignedContingentInputBuilder::new(
            block_version,
            input_credentials,
            fog_resolver,
            EmptyMemoBuilder::default(),
        )?;

        let change_destination = ReservedSubaddresses::from(&self.account_key);

        if allow_partial_fill {
            sci_builder
                .add_partial_fill_output(requested, &self.account_key.default_subaddress(), rng)
                .map_err(Error::AddOutput)?;
            sci_builder
                .add_partial_fill_change_output(offered, &change_destination, rng)
                .map_err(Error::AddOutput)?;
        } else {
            sci_builder
                .add_required_output(requested, &self.account_key.default_subaddress(), rng)
                .map_err(Error::AddOutput)?;
        }

        sci_builder
            .add_required_change_output(change, &change_destination, rng)
            .map_err(|err| {
                log::error!(self.logger, "Could not add change due to {:?}", err);
                Error::AddOutput(err)
            })?;

        sci_builder.set_tombstone_block(tombstone_block);

        let ring_signer = LocalRingSigner::from(&self.account_key);
        Ok(sci_builder.build(&ring_signer, rng)?)
    }

    /// Builds a transaction that fulfills a swap request, sending all excess
    /// funds to ourselves and paying fee.
    ///
    /// # Arguments
    /// * `sci` - The swap request we are fulfilling.
    /// * `fill_amount` - The amount of the SCI we are taking, if it is a partial fill SCI.
    ///                   This ranges from 0 up to the value of the fractional change output,
    ///                   and in the latter case means we fully consume the SCI.
    ///                   This must be None if this is not a partial fill SCI.
    /// * `fee` - The transaction fee to use.
    /// * `rng` - Randomness.
    pub fn build_swap_transaction<T: RngCore + CryptoRng>(
        &mut self,
        mut sci: SignedContingentInput,
        fill_amount: Option<Amount>,
        fee: Amount,
        rng: &mut T,
    ) -> Result<Tx> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.build_swap_transaction");

        // Validate the sci
        sci.validate()?;

        // Check if its key image alreay landed
        //
        // Note: An actual fog wallet may not want to do this part, because it adds to
        // latency, but if you have a local ledger copy you should definitely do this
        //
        // Note: It is still a racy check though -- the sci may expire while you are
        // still submitting an order that uses it. So this check doesn't guarantee that
        // your submission will work.
        let res = self.fog_key_image.check_key_images(&[sci.key_image()])?;
        if res.results[0].key_image_result_code == KeyImageResultCode::Spent as u32 {
            return Err(Error::SciExpired);
        }
        // Do tombstone block calculation using this key image query result rather than
        // make another call using `self.compute_tombstone_block`.
        let tombstone_block = res.num_blocks + self.new_tx_block_attempts as u64;

        // Update sci's merkle proofs
        sci.tx_in.proofs.clear();
        let merkle_root_block = 0u64;
        for (idx, result) in self
            .fog_merkle_proof
            .get_outputs(sci.tx_out_global_indices.clone(), merkle_root_block)?
            .results
            .into_iter()
            .enumerate()
        {
            if result.index != sci.tx_out_global_indices[idx] {
                return Err(Error::FogMerkleProof(
                    "Server returned indices in an unexpected order".to_string(),
                ));
            }
            match result.status() {
                Err(err) => {
                    return Err(Error::FogMerkleProof(format!(
                        "Server failed to compute a merkle proof: {}",
                        err
                    )))
                }
                Ok(None) => {
                    return Err(Error::FogMerkleProof(
                        "Server did not find one of the outputs we need".to_string(),
                    ))
                }
                Ok(Some((tx_out, proof))) => {
                    if sci.tx_in.ring[idx] != tx_out {
                        log::debug!(
                            self.logger,
                            "Expected: {:?}, Found: {:?}",
                            sci.tx_in.ring[idx],
                            tx_out
                        );
                        return Err(Error::SciGlobalIndexTxOutMismatch(
                            sci.tx_out_global_indices[idx],
                        ));
                    }
                    sci.tx_in.proofs.push(proof);
                }
            }
        }

        // Make fog resolver
        let fog_uris = self
            .account_key
            .fog_report_url()
            .map(FogUri::from_str)
            .transpose()?;
        let fog_responses = self
            .fog_report_conn
            .fetch_fog_reports(fog_uris.into_iter())?;
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_verifier)?;

        let block_version = BlockVersion::try_from(self.tx_data.get_latest_block_version())?;

        let change_destination = ReservedSubaddresses::from(&self.account_key);

        // Make transaction builder
        // TODO: Use RTH memos
        let mut tx_builder = TransactionBuilder::new(
            block_version,
            fee,
            fog_resolver,
            EmptyMemoBuilder::default(),
        )?;
        tx_builder.set_tombstone_block(tombstone_block);

        // Aggregate total required outlay due to the SCI
        // (Note: In the partial fill case, there will be more outlays later)
        let mut outlay: HashMap<TokenId, u64> = Default::default();
        outlay.insert(fee.token_id, fee.value);
        for req_amount in sci.required_output_amounts.iter() {
            *outlay
                .entry(TokenId::from(req_amount.token_id))
                .or_default() += req_amount.value;
        }

        let sci_token_id = TokenId::from(sci.pseudo_output_amount.token_id);
        let sci_value = sci.pseudo_output_amount.value;

        // Now we have to case out on the partial-fill vs. non-partial fill flow
        if let Some(fill_amount) = fill_amount {
            // Compute the parameter that we need to pass to the sci builder
            // FIXME: Don't unwrap here
            let (partial_fill_change, _) = sci.tx_in.input_rules.as_ref().unwrap().partial_fill_change.as_ref().unwrap().reveal_amount().unwrap();

            if partial_fill_change.token_id != fill_amount.token_id {
                return Err(Error::SciTokenIdMismatch);
            }

            let sci_change_amount = Amount::new(partial_fill_change.value - fill_amount.value, fill_amount.token_id);

            // Add the SCI to the tx builder, it will return the fractional amounts it computed for each
            // fractional output that was required.
            let fractional_amounts = tx_builder.add_presigned_partial_fill_input(sci, sci_change_amount)?;

            // Record the outlays that came from the fractional outputs
            for fractional_amount in fractional_amounts {
                *outlay.entry(fractional_amount.token_id)
                .or_default() += fractional_amount.value;
            }

            // Record the outlay that came from the fractional change
            *outlay.entry(sci_change_amount.token_id).or_default() += sci_change_amount.value;
        } else {
            // Add the presigned input
            // There's nothing else to do if there's no partial fill component.
            tx_builder.add_presigned_input(sci)?;
        }

        // Compute the leftover from the signed input.
        // For example, the signed input may provide some amount of token_id1,
        // but it may also have required outputs in token_id1 (for example as change)
        // If present that is the "matching outlay".
        // The remainder of subtracting the matching output from the signed input
        // value is the leftover, which is the incentive to us to fill the order.
        //
        // If the leftover would be negative, then this is returned as an error
        // SciUnprofitable. To make this concrete, this means that an order e.g.
        // offers an input worth 10 MOB, but requires an output worth 20 MOB, so
        // net, they not offering you anything and just asking for MOB. We could
        // implement support for filling such orders, but since it seems uninteresting
        // we decided to skip this and write less code for ourselves to maintain,
        // and just return an error instead.
        let leftover = {
            // The matching outlay is how much required outlay there is in the
            // token id of the signed input.
            //
            // We will use outlay list later to search our own wallet for required amounts,
            // but we don't need to do that for this token id -- the "outlay" is
            // actually negative taking into accoun the SCI input value, we have
            // leftover value instead which we will add to ourselves as an
            // output.
            let matching_outlay = outlay.remove(&sci_token_id).unwrap_or(0);

            // If the offered amount is less than the matching outlay, then the
            // leftover would be negative, and it is unprofitable to fill this
            // order, since they aren't actually offering any value.
            if sci_value < matching_outlay {
                return Err(Error::SciUnprofitable);
            }

            // This is the amount that will be leftover which we can send to ourselves,
            // and is our incentive to fill the order
            Amount::new(sci_value - matching_outlay, sci_token_id)
        };

        // Pay the leftover to ourselves
        tx_builder.add_change_output(leftover, &change_destination, rng)?;

        // Contribute our own inputs that may be required to fulfill the order
        for (token_id, value) in outlay {
            // Arbitrarily choose 3 as the maximum number of inputs
            // TODO: Should be based on fee scaling and fee choice
            const TARGET_NUM_INPUTS: usize = 3;
            let inputs = self
                .tx_data
                .get_transaction_inputs(Amount::new(value, token_id), TARGET_NUM_INPUTS)?;

            let total_input_value: u64 = inputs
                .iter()
                .map(|owned_tx_out| owned_tx_out.amount.value)
                .sum();

            let inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = self.get_proofs(&inputs)?;
            let rings: Vec<Vec<(TxOut, TxOutMembershipProof)>> = self.get_rings(&inputs, rng)?;

            // Add the inputs we selected for this token id
            add_inputs_to_tx_builder(&mut tx_builder, inputs, rings, &self.account_key)?;

            // Pay change in this token id back to ourselves
            tx_builder.add_change_output(
                Amount::new(total_input_value - value, token_id),
                &change_destination,
                rng,
            )?;
        }

        let ring_signer = LocalRingSigner::from(&self.account_key);
        Ok(tx_builder.build(&ring_signer, rng)?)
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
        let outputs_and_proofs = self
            .fog_merkle_proof
            .get_outputs(indices.clone(), merkle_root_block)?
            .results
            .iter()
            .cloned()
            .enumerate()
            .map(|(idx, result)| {
                if result.index != indices[idx] {
                    return Err(Error::FogMerkleProof(
                        "Server returned indices in an unexpected order".to_string(),
                    ));
                }
                match result.status() {
                    Err(err) => Err(Error::FogMerkleProof(format!(
                        "Server failed to compute a merkle proof: {}",
                        err
                    ))),
                    Ok(None) => Err(Error::FogMerkleProof(
                        "Server did not find one of the outputs we need".to_string(),
                    )),
                    Ok(Some(res)) => Ok(res),
                }
            })
            .collect::<Result<Vec<(TxOut, TxOutMembershipProof)>>>()?;

        log::info!(self.logger, "Retrieved {} TXOs", outputs_and_proofs.len());

        assert_eq!(outputs_and_proofs.len(), inputs.len());

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
        true_inputs: &[(OwnedTxOut, TxOutMembershipProof)],
        rng: &mut T,
    ) -> Result<Vec<Vec<(TxOut, TxOutMembershipProof)>>> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_rings");

        let true_input_indices: HashSet<u64> = true_inputs
            .iter()
            .map(|input| input.0.global_index)
            .collect();

        let num_rings = true_inputs.len();
        let num_requested = num_rings * self.ring_size;
        let sample_limit = self.tx_data.get_global_txo_count() as usize;

        // Randomly sample `num_requested` TxOuts, without replacement, not using
        // true_inputs
        if sample_limit < num_requested + true_inputs.len() {
            return Err(Error::InsufficientTxOutsInBlockchain(
                sample_limit,
                num_requested + true_inputs.len(),
            ));
        }

        let mut sampled_indices: HashSet<u64> = HashSet::default();
        while sampled_indices.len() < num_requested {
            let index = rng.gen_range(0..sample_limit) as u64;
            if !true_input_indices.contains(&index) {
                sampled_indices.insert(index);
            }
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

    /// Retrieve the current last block info structure from consensus service.
    /// This includes fee data and last block index, and the configured block
    /// version
    pub fn get_last_block_info(&mut self) -> Result<BlockInfo> {
        let block_info = self.consensus_service_conn.fetch_block_info()?;
        // Opportunistically update our cached block version value
        self.tx_data
            .notify_block_version(block_info.network_block_version);
        Ok(block_info)
    }

    /// Retrieve the currently configured minimum fee for a token id from the
    /// consensus service
    pub fn get_minimum_fee(&mut self, token_id: TokenId) -> Result<Option<u64>> {
        Ok(self.get_last_block_info()?.minimum_fee_or_none(&token_id))
    }

    /// Get the public b58 address for this client
    pub fn get_b58_address(&self) -> String {
        let public_address = self.account_key.default_subaddress();

        let mut wrapper = mc_api::printable::PrintableWrapper::new();
        wrapper.set_public_address((&public_address).into());

        wrapper.b58_encode().unwrap()
    }
}

/// Builds a transaction that spends `inputs`, sends `amount` to the recipient,
/// and returns the remainder to the sender minus the transaction fee.
///
/// # Arguments
/// * `block_version` - The block version to target
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
fn build_transaction_helper<T: RngCore + CryptoRng>(
    block_version: BlockVersion,
    inputs: Vec<(OwnedTxOut, TxOutMembershipProof)>,
    rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
    amount: Amount,
    source_account_key: &AccountKey,
    target_address: &PublicAddress,
    tombstone_block: BlockIndex,
    fog_resolver: impl FogPubkeyResolver,
    ring_signer: &impl RingSigner,
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

    // Use the RTHMemoBuilder
    // Note: Memos are disabled if we target an older block version
    let mut tx_builder = {
        let mut memo_builder = RTHMemoBuilder::default();
        memo_builder.set_sender_credential(SenderMemoCredential::from(source_account_key));
        memo_builder.enable_destination_memo();

        TransactionBuilder::new(
            block_version,
            Amount::new(fee, amount.token_id),
            fog_resolver,
            memo_builder,
        )?
    };

    // Check amount found, calculate change
    let input_amount = inputs
        .iter()
        .fold(0, |acc, (txo, _)| acc + txo.amount.value);
    let fee = tx_builder.get_fee();
    if (amount.value + fee) > input_amount {
        return Err(Error::InsufficientFunds);
    }
    let change = input_amount - (amount.value + fee);

    // Add inputs
    add_inputs_to_tx_builder(&mut tx_builder, inputs, rings, source_account_key)?;

    // Add output
    tx_builder
        .add_output(amount, target_address, rng)
        .map_err(Error::AddOutput)?;

    // Add change output
    let change_destination = ReservedSubaddresses::from(source_account_key);
    tx_builder
        .add_change_output(
            Amount::new(change, amount.token_id),
            &change_destination,
            rng,
        )
        .map_err(|err| {
            log::error!(logger, "Could not add change due to {:?}", err);
            Error::AddOutput(err)
        })?;

    // Finalize
    tx_builder.set_tombstone_block(tombstone_block);

    Ok(tx_builder.build(ring_signer, rng)?)
}

fn add_inputs_to_tx_builder<FPR: FogPubkeyResolver>(
    tx_builder: &mut TransactionBuilder<FPR>,
    inputs: Vec<(OwnedTxOut, TxOutMembershipProof)>,
    rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
    source_account_key: &AccountKey,
) -> Result<()> {
    // Unzip each vec of tuples into a tuple of vecs.
    let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
        .into_iter()
        .map(|tuples| tuples.into_iter().unzip())
        .collect();

    for (input_txo, input_proof) in inputs {
        let (ring, membership_proofs) = rings_and_proofs
            .pop()
            .expect("Consistency failure converting vec of tuple into tuple of vecs");
        assert_eq!(
            ring.len(),
            membership_proofs.len(),
            "Each ring element must have a corresponding membership proof."
        );

        tx_builder.add_input(input_credentials_helper(
            input_txo,
            input_proof,
            ring,
            membership_proofs,
            source_account_key,
        )?);
    }

    Ok(())
}

// Helper which builds `InputCredentials` given owned txo, and the results
// of get_proofs, get_rings, and the account key which it uses to derive the
// one-time private key.
fn input_credentials_helper(
    input_txo: OwnedTxOut,
    input_proof: TxOutMembershipProof,
    mut ring: Vec<TxOut>,
    mut membership_proofs: Vec<TxOutMembershipProof>,
    source_account_key: &AccountKey,
) -> Result<InputCredentials> {
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
                membership_proofs.push(input_proof);
            } else {
                // Replace the first element of the ring.
                ring[0] = input_txo.tx_out.clone();
                membership_proofs[0] = input_proof;
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

    let ring_len = ring.len();
    InputCredentials::new(
        ring,
        membership_proofs,
        real_key_index,
        OneTimeKeyDeriveData::SubaddressIndex(input_txo.subaddress_index),
        *source_account_key.view_private_key(),
    )
    .or(Err(Error::BrokenRing(ring_len, real_key_index)))
}

#[cfg(test)]
mod test_build_transaction_helper {
    use super::*;
    use core::result::Result as StdResult;
    use mc_account_keys::{AccountKey, PublicAddress, DEFAULT_SUBADDRESS_INDEX};
    use mc_common::logger::{test_with_logger, Logger};
    use mc_crypto_keys::RistrettoPublic;
    use mc_fog_report_validation::{FogPubkeyError, FullyValidatedFogPubkey};
    use mc_fog_types::view::{FogTxOut, FogTxOutMetadata, TxOutRecord};
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, onetime_keys::recover_public_subaddress_spend_key,
        tokens::Mob, tx::TxOut, Amount, Token,
    };
    use mc_transaction_core_test_utils::get_outputs;
    use mc_util_test_helper::get_seeded_rng;

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
        let mut rng = get_seeded_rng();

        for block_version in BlockVersion::iterator() {
            let sender_account_key = AccountKey::random(&mut rng);
            let sender_public_address = sender_account_key.default_subaddress();

            // Amount per input.
            let initial_amount = Amount::new(300 * MILLIMOB_TO_PICOMOB, Mob::ID);
            let amount_to_send = Amount::new(457 * MILLIMOB_TO_PICOMOB, Mob::ID);
            let num_inputs = 3;
            let ring_size = 1;

            // Create inputs.
            let inputs = {
                let recipient_and_amount = (0..num_inputs)
                    .map(|_| (sender_public_address.clone(), initial_amount))
                    .collect::<Vec<_>>();
                let outputs = get_outputs(block_version, &recipient_and_amount, &mut rng);

                let cached_inputs: Vec<(OwnedTxOut, TxOutMembershipProof)> = outputs
                    .into_iter()
                    .map(|tx_out| {
                        let fog_tx_out = FogTxOut::try_from(&tx_out).unwrap();
                        let meta = FogTxOutMetadata::default();
                        let txo_record = TxOutRecord::new(fog_tx_out, meta);

                        let tx_out_target_key =
                            RistrettoPublic::try_from(&tx_out.target_key).unwrap();
                        let tx_public_key = RistrettoPublic::try_from(&tx_out.public_key).unwrap();

                        let subaddress_spk = recover_public_subaddress_spend_key(
                            sender_account_key.view_private_key(),
                            &tx_out_target_key,
                            &tx_public_key,
                        );
                        let spsk_to_index =
                            HashMap::from_iter(vec![(subaddress_spk, DEFAULT_SUBADDRESS_INDEX)]);

                        let owned_tx_out =
                            OwnedTxOut::new(txo_record, &sender_account_key, &spsk_to_index)
                                .unwrap();

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
                    let recipient_and_amount = (0..ring_size)
                        .map(|_| (sender_public_address.clone(), Amount::new(33, Mob::ID)))
                        .collect::<Vec<_>>();
                    get_outputs(block_version, &recipient_and_amount, &mut rng)
                };
                assert_eq!(ring.len(), ring_size);
                rings.push(ring);
            }

            assert_eq!(inputs.len(), rings.len());

            let mut rings_and_membership_proofs: Vec<Vec<(TxOut, TxOutMembershipProof)>> =
                Vec::new();
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
                block_version,
                inputs,
                rings_and_membership_proofs,
                amount_to_send,
                &sender_account_key,
                &recipient_account_key.default_subaddress(),
                super::BlockIndex::max_value(),
                fake_acct_resolver,
                &LocalRingSigner::from(&sender_account_key),
                &mut rng,
                &logger,
                Mob::MINIMUM_FEE,
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
    }

    #[test]
    #[ignore]
    // `build_transaction_helper` should return a Tx when `rings` contains an input.
    fn test_build_transaction_helper_rings_intersect_inputs() {
        unimplemented!()
    }

    // TODO: error conditions for builder_transaction_helper
}
