// Copyright (c) 2018-2023 The MobileCoin Foundation

//! MobileCoin Client Object

use crate::{
    cached_tx_data::{CachedTxData, OwnedTxOut},
    error::{Error, Result},
    BlockInfo, MemoHandlerError, TransactionStatus,
};
use core::{result::Result as StdResult, str::FromStr};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_api::printable::printable_wrapper;
use mc_attestation_verifier::TrustedIdentity;
use mc_blockchain_types::{BlockIndex, BlockVersion};
use mc_common::logger::{log, Logger};
use mc_connection::{
    BlockchainConnection, Connection, Error as ConnectionError, HardcodedCredentialsProvider,
    ProposeTxResult, ThickClient, UserTxConnection,
};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_crypto_ring_signature_signer::{LocalRingSigner, OneTimeKeyDeriveData, RingSigner};
use mc_fog_api::fog_ledger::TxOutResultCode;
use mc_fog_ledger_connection::{
    FogBlockGrpcClient, FogKeyImageGrpcClient, FogMerkleProofGrpcClient,
    FogUntrustedLedgerGrpcClient, OutputResultExtension,
};
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_report_resolver::FogResolver;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_fog_types::{ledger::KeyImageResultCode, BlockCount};
use mc_fog_view_connection::FogViewGrpcClient;
use mc_rand::CryptoRng;
use mc_transaction_builder::{
    EmptyMemoBuilder, InputCredentials, RTHMemoBuilder, ReservedSubaddresses,
    SignedContingentInputBuilder, TransactionBuilder,
};
use mc_transaction_core::{
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, FeeMap, TokenId,
};
use mc_transaction_extra::{MemoType, SenderMemoCredential, SignedContingentInput};
use mc_util_uri::{ConnectionUri, FogUri};
use rand::{seq::SliceRandom, RngExt};
use std::collections::{hash_map::Entry, HashMap, HashSet};

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
    fog_block: FogBlockGrpcClient,
    fog_report_conn: GrpcFogReportConnection,
    fog_identities: Vec<TrustedIdentity>,
    fog_untrusted: FogUntrustedLedgerGrpcClient,
    ring_size: usize,
    account_key: AccountKey,
    tx_data: CachedTxData,
    block_info_cache: Option<BlockInfo>,

    /// What we remember about each of our inputs (keyed by global index) that
    /// has been part of a transaction: the indices the fog ledger operator
    /// first saw it with, and the mixins currently used for it. Consulted on
    /// every build so that linked `GetOutputs` requests cannot narrow down
    /// which ring members are real, see `get_inputs_and_rings`.
    ring_cache: HashMap<u64, CachedInput>,

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
        fog_identities: impl Into<Vec<TrustedIdentity>>,
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
            fog_identities: fog_identities.into(),
            fog_untrusted,
            ring_size,
            account_key,
            tx_data,
            block_info_cache: None,
            ring_cache: Default::default(),
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
        let block_count = self
            .consensus_service_conn
            .propose_tx(transaction)
            .map_err(|err| {
                if let ConnectionError::TransactionValidation(
                    ProposeTxResult::FeeMapDigestMismatch,
                    _,
                ) = err
                {
                    // Clear block_info cache so that fee map info will be regenerated
                    // next time.
                    //
                    // NOTE: In a real client, what you should actually do is check
                    // with several nodes what the fee map is supposed to be,
                    // to defend against the TOB-MCCT-5 attack.
                    // If you get differing answers then you know the network is in
                    // a bad state. Nodes cannot peer if they do not agree on the
                    // fee map, so this means an attack or some kind of fork is
                    // happening.
                    //
                    // The sample paykit is just test code, and it only has one url
                    // for a consensus node in this revision, so we don't do that
                    // here, we just reset the fee map.
                    self.block_info_cache = None;
                }

                err
            })?;

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
                                            "Server reported our request {public_key:?} was malformed"
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
                                        panic!("Server returned an unknown status code: {other}");
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
    pub fn build_transaction<T: CryptoRng>(
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
        let (inputs, rings) = self.get_inputs_and_rings(&inputs, false, rng)?;

        let tombstone_block = self.compute_tombstone_block()?;

        let block_version = BlockVersion::try_from(self.tx_data.get_latest_block_version())?;

        let fee_map = self.get_fee_map(true)?;

        // Make fog resolver
        let fog_uris = [&self.account_key.change_subaddress(), target_address]
            .iter()
            .filter_map(|addr| addr.fog_report_url())
            .map(FogUri::from_str)
            .collect::<core::result::Result<Vec<_>, _>>()?;
        let fog_responses = self
            .fog_report_conn
            .fetch_fog_reports(fog_uris.into_iter())?;
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_identities)?;

        let ring_signer = LocalRingSigner::from(&self.account_key);

        build_transaction_helper(
            block_version,
            fee_map,
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
    pub fn build_swap_proposal<T: CryptoRng>(
        &mut self,
        offered: Amount,
        requested: Amount,
        allow_partial_fill: bool,
        rng: &mut T,
    ) -> Result<SignedContingentInput> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.build_swap_proposal");

        // Only one input can be used, otherwise defragmentation is required
        let inputs = self.tx_data.get_transaction_inputs(offered, 1)?;
        let (inputs, rings) = self.get_inputs_and_rings(&inputs, true, rng)?;

        assert_eq!(inputs.len(), 1);
        assert_eq!(rings.len(), 1);

        let (input, input_proof) = inputs[0].clone();
        let ring = rings[0].clone();

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
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_identities)?;

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
            EmptyMemoBuilder,
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
    /// * `fill_amount` - The amount of the SCI we are taking, if it is a
    ///   partial fill SCI. This ranges from 0 up to the value of the fractional
    ///   change output, and in the latter case means we fully consume the SCI.
    ///   This must be None if this is not a partial fill SCI.
    /// * `fee` - The transaction fee to use.
    /// * `rng` - Randomness.
    pub fn build_swap_transaction<T: CryptoRng>(
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
                        "Server failed to compute a merkle proof: {err}"
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
        let fog_resolver = FogResolver::new(fog_responses, &self.fog_identities)?;

        let block_version = BlockVersion::try_from(self.tx_data.get_latest_block_version())?;

        let change_destination = ReservedSubaddresses::from(&self.account_key);

        // Make transaction builder
        let mut tx_builder = TransactionBuilder::new(block_version, fee, fog_resolver)?;
        tx_builder.set_tombstone_block(tombstone_block);

        tx_builder.set_fee_map(self.get_fee_map(true)?);

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
            let (partial_fill_change, _) = sci
                .tx_in
                .input_rules
                .as_ref()
                .unwrap()
                .partial_fill_change
                .as_ref()
                .unwrap()
                .reveal_amount()
                .unwrap();

            if partial_fill_change.token_id != fill_amount.token_id {
                return Err(Error::SciTokenIdMismatch);
            }

            let sci_change_amount = Amount::new(
                partial_fill_change.value - fill_amount.value,
                fill_amount.token_id,
            );

            // Add the SCI to the tx builder, it will return the fractional amounts it
            // computed for each fractional output that was required.
            let fractional_amounts =
                tx_builder.add_presigned_partial_fill_input(sci, sci_change_amount)?;

            // Record the outlays that came from the fractional outputs
            for fractional_amount in fractional_amounts {
                *outlay.entry(fractional_amount.token_id).or_default() += fractional_amount.value;
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

        // Contribute our own inputs that may be required to fulfill the order.
        // The inputs for all token ids are selected first and their rings are
        // fetched together, so that no mixin ends up in two of our rings, which
        // the network would reject.
        //
        // Arbitrarily choose 3 as the maximum number of inputs per token id
        // TODO: Should be based on fee scaling and fee choice
        const TARGET_NUM_INPUTS: usize = 3;
        let mut inputs = Vec::new();
        let mut change_amounts = Vec::new();
        for (token_id, value) in outlay {
            let token_inputs = self
                .tx_data
                .get_transaction_inputs(Amount::new(value, token_id), TARGET_NUM_INPUTS)?;

            let total_input_value: u64 = token_inputs
                .iter()
                .map(|owned_tx_out| owned_tx_out.amount.value)
                .sum();

            // Change in this token id goes back to ourselves
            change_amounts.push(Amount::new(total_input_value - value, token_id));
            inputs.extend(token_inputs);
        }

        if !inputs.is_empty() {
            let (inputs, rings) = self.get_inputs_and_rings(&inputs, false, rng)?;
            add_inputs_to_tx_builder(&mut tx_builder, inputs, rings, &self.account_key)?;
        }

        for change in change_amounts {
            tx_builder.add_change_output(change, &change_destination, rng)?;
        }

        let ring_signer = LocalRingSigner::from(&self.account_key);
        // TODO: Use RTH memos
        Ok(tx_builder.build(&ring_signer, EmptyMemoBuilder, rng)?)
    }

    /// Helper: Fetch merkle proofs for our true inputs and sample rings of
    /// mixins for them, using a single `GetOutputs` request.
    ///
    /// The fog ledger merkle proof service is not oblivious: the untrusted
    /// server process sees every index that is requested. Requesting the true
    /// inputs on their own (and the mixins in a separate request) would tell
    /// the operator exactly which ring member is real. Instead, the true input
    /// indices are shuffled in among the mixin indices and sent together, so
    /// a single request only reveals the ring membership. (Note that rings do
    /// not reach the chain: a block contains only key images and outputs.
    /// Apart from the counterparty of a signed contingent input, the fog
    /// ledger operator is the only party outside the consensus enclave that
    /// ever sees them, so the shape of these requests is all that protects
    /// them.)
    ///
    /// That is not enough on its own: if a transaction is built more than once
    /// with the same inputs (a retry, a rebuild with a different fee, an
    /// abandoned build), re-sampling the mixins each time would let the
    /// operator intersect the requests and recover exactly the true inputs.
    /// So the mixins chosen for each input are remembered in `self.ring_cache`
    /// for as long as this client lives, and every later request involving an
    /// input also includes the ring the operator first saw it in. See
    /// `select_mixin_indices` for the exact guarantee, its one exception, and
    /// how it is kept.
    ///
    /// # Arguments
    /// * inputs: The OwnedTxOut records we intend to spend
    /// * for_proposal: true if the rings will leave the client (in a signed
    ///   contingent input), see `select_mixin_indices`
    /// * rng: randomness
    ///
    /// # Returns
    /// * The inputs, with their TxOut replaced by the copy from the ledger and
    ///   paired with a membership proof. (The TxOut from fog view lacks the
    ///   hint field, so submitting it would fail the merkle proof check.)
    /// * One ring per input, each of `self.ring_size` elements, where the first
    ///   element is the true input.
    #[allow(clippy::type_complexity)]
    fn get_inputs_and_rings<T: CryptoRng>(
        &mut self,
        inputs: &[OwnedTxOut],
        for_proposal: bool,
        rng: &mut T,
    ) -> Result<(
        Vec<(OwnedTxOut, TxOutMembershipProof)>,
        Vec<Vec<(TxOut, TxOutMembershipProof)>>,
    )> {
        mc_common::trace_time!(self.logger, "MobileCoinClient.get_inputs_and_rings");

        let real_indices: Vec<u64> = inputs.iter().map(|input| input.global_index).collect();

        // Each ring is the true input plus (ring_size - 1) mixins.
        let RingSelection {
            mixins: mixin_indices,
            mut request_indices,
        } = select_mixin_indices(
            &real_indices,
            for_proposal,
            &mut self.ring_cache,
            self.ring_size.saturating_sub(1),
            self.tx_data.get_global_txo_count(),
            rng,
        )?;

        // Shuffle before asking the server
        request_indices.shuffle(rng);

        // FIXME: We are not sure whether this is a necessary parameter under ORAM.
        let merkle_root_block: u64 = 0;

        log::debug!(
            self.logger,
            "Sending LedgerConnection:GetOutputs {request_indices:?}"
        );
        let mut outputs_and_proofs: HashMap<u64, (TxOut, TxOutMembershipProof)> = self
            .fog_merkle_proof
            .get_outputs(request_indices.clone(), merkle_root_block)?
            .results
            .iter()
            .enumerate()
            .map(|(idx, result)| {
                if request_indices.get(idx) != Some(&result.index) {
                    return Err(Error::FogMerkleProof(
                        "Server returned indices in an unexpected order".to_string(),
                    ));
                }
                match result.status() {
                    Err(err) => Err(Error::FogMerkleProof(format!(
                        "Server failed to compute a merkle proof: {err}"
                    ))),
                    Ok(None) => Err(Error::FogMerkleProof(
                        "Server did not find one of the outputs we need".to_string(),
                    )),
                    Ok(Some(res)) => Ok((result.index, res)),
                }
            })
            .collect::<Result<_>>()?;

        if outputs_and_proofs.len() != request_indices.len() {
            return Err(Error::FogMerkleProof(
                "Server returned an unexpected number of outputs".to_string(),
            ));
        }

        let mut take = |index: u64| {
            outputs_and_proofs.remove(&index).ok_or_else(|| {
                Error::FogMerkleProof(format!("Server response is missing index {index}"))
            })
        };

        let mut inputs_with_proofs = Vec::with_capacity(inputs.len());
        let mut rings = Vec::with_capacity(inputs.len());
        for (input, mixins) in inputs.iter().zip(mixin_indices.iter()) {
            let (tx_out, proof) = take(input.global_index)?;
            let mut ring = Vec::with_capacity(self.ring_size);
            ring.push((tx_out.clone(), proof.clone()));
            for mixin in mixins {
                ring.push(take(*mixin)?);
            }
            rings.push(ring);

            let mut input = input.clone();
            input.tx_out = tx_out;
            inputs_with_proofs.push((input, proof));
        }

        log::info!(
            self.logger,
            "Retrieved {} inputs and {} rings",
            inputs_with_proofs.len(),
            rings.len()
        );
        Ok((inputs_with_proofs, rings))
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
    ///
    /// This includes fee data and last block index, and the configured block
    /// version
    ///
    /// Arguments:
    /// * allow_cached If true, then we may skip a network call and use cached
    ///   value.
    pub fn get_last_block_info(&mut self, allow_cached: bool) -> Result<BlockInfo> {
        // Clear cache if we aren't allowed to use it, it will be repopulated in this
        // call.
        if !allow_cached {
            self.block_info_cache = None;
        }
        // Check if we know our cache is stale for other reasons, like if fog responses
        // told us the block version has increased.
        if let Some(block_info_cache) = self.block_info_cache.as_ref() {
            if block_info_cache.network_block_version != self.tx_data.get_latest_block_version() {
                self.block_info_cache = None;
            }
        }

        if self.block_info_cache.is_none() {
            let block_info = self.consensus_service_conn.fetch_block_info()?;
            // Opportunistically update our cached block version value
            self.tx_data
                .notify_block_version(block_info.network_block_version);
            self.block_info_cache = Some(block_info);
        }

        let block_info = self.consensus_service_conn.fetch_block_info()?;
        Ok(block_info)
    }

    /// Get the currently cached fee-map
    ///
    /// If the cache is empty, then we get fresh data from consensus.
    pub fn get_fee_map(&mut self, allow_cached: bool) -> Result<FeeMap> {
        let block_info = self.get_last_block_info(allow_cached)?;
        let fee_map = FeeMap::try_from(block_info.minimum_fees)?;
        Ok(fee_map)
    }

    /// Retrieve the currently configured minimum fee for a token id from the
    /// consensus service
    pub fn get_minimum_fee(
        &mut self,
        token_id: TokenId,
        allow_cached: bool,
    ) -> Result<Option<u64>> {
        Ok(self
            .get_last_block_info(allow_cached)?
            .minimum_fee_or_none(&token_id))
    }

    /// Get the public b58 address for this client
    pub fn get_b58_address(&self) -> String {
        let public_address = self.account_key.default_subaddress();

        let wrapper = mc_api::printable::PrintableWrapper {
            wrapper: Some(printable_wrapper::Wrapper::PublicAddress(
                (&public_address).into(),
            )),
        };

        wrapper.b58_encode()
    }
}

/// How large an earlier request we are willing to send again, in rings.
///
/// Sometimes an output of ours has already been sent to the fog ledger in an
/// earlier request, as a mixin for another input. When we later spend that
/// output, the safest ring request is the earlier request's indices again, so
/// the operator learns nothing new. The indices remembered for an input are
/// the ones it was first sent with plus its current mixins, which can change
/// over time, so that set can be larger than one ring. Sets up to this many
/// rings are resent; a larger one is left alone and the output gets a fresh
/// ring instead, accepting the privacy loss documented in
/// `select_mixin_indices`.
///
/// With ring size 11, this allows 22 indices. An input whose mixins have all
/// been swapped once needs 11 + 10 = 21.
const MAX_REUSED_REQUEST_RINGS: usize = 2;

/// What the client remembers about an input that has been part of a
/// transaction before. See `select_mixin_indices`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct CachedInput {
    /// The indices the fog ledger operator first saw this input among: its own
    /// first ring, or, if it turned out to have been a mixin for an earlier
    /// input of ours, everything remembered for that input. Never changes, and
    /// is sent again in every later request involving this input. Swap
    /// proposals use its first ring_size - 1 members other than the input as
    /// the ring, so a reused set is shuffled once before it is stored here.
    first_request: Vec<u64>,
    /// The mixins currently used for this input in transactions. Initially
    /// taken from `first_request`, leaving out the input. A mixin is replaced
    /// only when it collides with another input of the same transaction or
    /// with one of its other rings.
    mixins: Vec<u64>,
}

impl CachedInput {
    /// Everything a request involving this input contains: the first request
    /// plus the current mixins, without duplicates.
    fn request(&self) -> HashSet<u64> {
        self.first_request
            .iter()
            .chain(&self.mixins)
            .cloned()
            .collect()
    }

    /// The mixins used for the ring that leaves the client in a signed
    /// contingent input (a swap proposal): the same every time, and always
    /// part of `first_request`.
    ///
    /// # Arguments
    /// * `input` - the global index of this input, which is left out of its own
    ///   ring
    /// * `num_mixins` - how many mixins the ring needs (ring size - 1)
    fn sci_mixins(&self, input: u64, num_mixins: usize) -> Vec<u64> {
        self.first_request
            .iter()
            .cloned()
            .filter(|index| *index != input)
            .take(num_mixins)
            .collect()
    }
}

/// The result of `select_mixin_indices`
struct RingSelection {
    /// One list of `num_mixins_per_ring` mixin indices per true input, in the
    /// same order as the true inputs.
    mixins: Vec<Vec<u64>>,
    /// Every index to request from the fog ledger: for each input, its first
    /// request and its mixins. Sorted and free of duplicates; the caller
    /// shuffles it.
    request_indices: Vec<u64>,
}

/// Choose the mixins for a set of true inputs, and the indices to request from
/// the fog ledger for them.
///
/// # Privacy guarantee
///
/// The fog ledger operator sees the requested indices and may link requests
/// from the same wallet. Fresh mixins on each rebuild would let it intersect
/// requests sharing a true input and potentially identify that input, even if
/// none of the transactions are submitted.
///
/// Once an input has a cache entry, every request selecting it as a true input
/// includes its remembered first request (`first_request`), usually its first
/// ring. This is the set remembered for this input; other inputs from the same
/// network request are tracked separately. A cached mixin must be replaced if
/// it is another true input in the transaction, or if it is already used in
/// another ordinary input's ring: the network rejects repeated ring members
/// across ordinary inputs. Even after such a replacement, the remembered first
/// request is still fetched in full. The intersection of these requests
/// therefore always contains that whole set, which blocks the repeated-build
/// attack. It does not stop the operator from guessing better than chance
/// within that set; the limits below describe what still leaks.
///
/// Our own outputs are eligible mixins too. If an output first appeared as a
/// mixin and is later selected as a true input, we try to reuse that earlier
/// input's first request plus its current mixins. Otherwise a fresh ring could
/// share only the newly selected input with the earlier request, identifying
/// it.
///
/// # Privacy tradeoff: the reuse size limit
///
/// Reusing earlier requests and then replacing mixins can grow the number of
/// indices fetched: a reused set carries over every index of the earlier
/// request, each later replacement adds one more, and an output of ours found
/// in the grown set would reuse all of it in turn. Without a cap, such a
/// chain has no upper bound, and the fog ledger accepts at most 2000 indices
/// per request. We only reuse sets of at most
/// `MAX_REUSED_REQUEST_RINGS * ring_size` indices (22 with the defaults),
/// which keeps a 16-input request at 512 indices or fewer.
/// A set only exceeds the cap after three unlikely events in a row: one of
/// our outputs sampled into our own ring (about one in a thousand per ring
/// for a wallet with 1,000 outputs on a 10M ledger), a replacement in the
/// reused set because it collided with another input or ring of ours (about
/// the same odds), and then another output of ours found in that grown set
/// (again about one in a thousand). The fallback below is therefore expected
/// far less than once in a million builds.
///
/// If every matching set is larger, we give the input a fresh ring instead.
/// That fresh ring and the earlier request have, barring a chance collision,
/// exactly one index in common: this input. An operator comparing the two
/// requests therefore learns that it is an output of ours. The size cap
/// deliberately accepts that to keep requests bounded. Later builds of this
/// input send the same fresh ring again and add nothing new, but the operator
/// already has the answer from the first comparison.
///
/// # Other limits
///
/// Request sizes and timing remain visible. Mixin replacements can enlarge
/// requests, revealing that rings changed; overlapping and reused requests can
/// also reveal relationships between wallet outputs. Remembering the first
/// request prevents simple set-intersection collapse, not all inference from
/// wallet activity. The protection lasts only while the cache is retained.
/// Recreating a client with an empty cache can expose inputs through fresh
/// rings; a wallet that needs protection across restarts must persist the
/// cache.
///
/// Rings are absent from blocks, but a swap proposal exposes its ring to the
/// counterparty. With `for_proposal`, the ring is always the same subset of
/// the remembered first request: its first ring_size - 1 members other than
/// the input. Reused requests are shuffled once so this subset is chosen at
/// random. Every later request selecting the input includes that proposal
/// ring, so intersecting its proposals and those requests retains the whole
/// ring. Proposal builds preserve the ordinary mixins for later lookups.
///
/// # Construction
///
/// Fresh mixins are sampled from the whole ledger. Two kinds of index that it
/// might seem natural to keep out of the sampling are deliberately left in:
///
/// * Our own outputs may be sampled as mixins. If they could not, a true input
///   of ours could never appear as a mixin, so an index that the rings of two
///   different inputs of ours happen to share would have to be a mixin in both,
///   and the operator could conclude that it is not an output of ours.
/// * Members of the ring of an SCI we are fulfilling may be sampled as mixins.
///   Consensus allows an SCI's ring to overlap our ordinary rings (MCIP 57), so
///   nothing forces us to keep them out. Doing so would also let the
///   counterparty, who picks that ring, force us to replace mixins of their
///   choosing, showing the operator which members were mixins.
///
/// A cached input contributes its first request plus at most ring_size - 1
/// current mixins. With 11 ring members and at most 16 inputs, the worst case
/// is 16 * (22 + 10) = 512 indices against the fog ledger's limit of 2000.
/// The cache is updated before the request is sent, so failed requests and
/// abandoned builds are accounted for too.
///
/// # Arguments
/// * `real_indices` - global indices of the true inputs, all distinct
/// * `for_proposal` - the rings will be shown to a counterparty, see above
/// * `ring_cache` - what we remember per true input, updated on return
/// * `num_mixins_per_ring` - how many mixins each ring needs
/// * `sample_limit` - fresh mixins are sampled from `0..sample_limit`
/// * `rng` - randomness
fn select_mixin_indices<T: CryptoRng>(
    real_indices: &[u64],
    for_proposal: bool,
    ring_cache: &mut HashMap<u64, CachedInput>,
    num_mixins_per_ring: usize,
    sample_limit: u64,
    rng: &mut T,
) -> Result<RingSelection> {
    let max_reused_len = MAX_REUSED_REQUEST_RINGS * (num_mixins_per_ring + 1);

    // Indices that may not be used as a mixin in this transaction. Grows as
    // mixins are assigned, so that no index ends up in two rings.
    let mut forbidden: HashSet<u64> = real_indices.iter().cloned().collect();

    // First pass: for each input, the mixins we would like, and the earlier
    // request it reuses if it was found in one. Mixins that are not allowed
    // (anymore) are dropped here and replaced by fresh samples below.
    let mut rings: Vec<Vec<u64>> = Vec::with_capacity(real_indices.len());
    let mut reused_requests: Vec<Option<Vec<u64>>> = Vec::with_capacity(real_indices.len());
    for real in real_indices {
        let (candidates, reused): (Vec<u64>, Option<Vec<u64>>) = if let Some(entry) =
            ring_cache.get(real)
        {
            let candidates = if for_proposal {
                entry.sci_mixins(*real, num_mixins_per_ring)
            } else {
                entry.mixins.clone()
            };
            (candidates, None)
        } else if let Some(request) = ring_cache
            .iter()
            // Linear scan: the cache is tiny. A wallet that persists it across
            // sessions might want an index -> input reverse map instead.
            .filter(|(_, entry)| entry.first_request.contains(real) || entry.mixins.contains(real))
            .map(|(input, entry)| (*input, entry.request()))
            .filter(|(_, request)| request.len() <= max_reused_len)
            .min_by_key(|(input, _)| *input)
            .map(|(_, request)| request)
        {
            // This input, which we own, was a mixin in that earlier request.
            // Reuse the request rather than sampling a fresh ring, which would
            // share exactly this input with it. Shuffled so that the ring taken
            // from it is a random choice (see `CachedInput`).
            //
            // Privacy: if the two inputs are later built together, that build
            // is abandoned, and one of them is then built alone, the operator
            // sees that two distinct inputs of ours are in this set (the
            // requests differ in size but share the set). The candidates for
            // each stay the whole set. A counterparty who holds proposals for
            // both learns the same. Needs one of our outputs to have been
            // sampled into our own ring in the first place. A ring draws
            // (ring size - 1) = 10 mixins uniformly from the ledger, so that is
            // about 10 * owned / ledger per ring: one in a thousand for a
            // wallet with 1,000 outputs on a 10M ledger.
            let mut request: Vec<u64> = request.into_iter().collect();
            request.shuffle(rng);
            let candidates = request
                .iter()
                .cloned()
                .filter(|index| index != real)
                .collect();
            (candidates, Some(request))
        } else {
            // Never seen before, or only in requests too large to reuse: a
            // fresh ring.
            //
            // Privacy: in the second case this input is the only index that
            // its earlier request and this one share, so the operator can
            // identify it as the real input. Needs two of our outputs sampled,
            // one after the other, into the same chain of rings. Each such
            // sampling is the one-in-a-thousand event above, so this is about
            // (10 * owned / ledger)^3 per ring: one in a million for a wallet
            // with 1,000 outputs on a 10M ledger.
            (Vec::new(), None)
        };
        // Privacy: dropping a remembered mixin here changes the ring. The first
        // request keeps the operator's candidates at the original ring, but
        // the request grows by the replacement, so the operator learns that a
        // replacement happened, and when two of our rings shared a mixin, that
        // the shared index was a mixin in one of them. Needs two independently
        // sampled rings to overlap: each of the 10 mixins of one against each
        // of the 10 of the other, about 10 * 10 / ledger per pair of rings,
        // one in a hundred thousand on a 10M ledger. Or one of our outputs in
        // our own ring (see above).
        let mut ring: Vec<u64> = candidates
            .into_iter()
            .filter(|mixin| !forbidden.contains(mixin))
            .collect();
        ring.truncate(num_mixins_per_ring);
        forbidden.extend(ring.iter().cloned());
        rings.push(ring);
        reused_requests.push(reused);
    }

    // Second pass: top the rings up with fresh samples and update the cache.
    let num_needed: usize = rings
        .iter()
        .map(|ring| num_mixins_per_ring - ring.len())
        .sum();
    let num_forbidden = forbidden
        .iter()
        .filter(|index| **index < sample_limit)
        .count();
    if (sample_limit as usize) < num_needed + num_forbidden {
        return Err(Error::InsufficientTxOutsInBlockchain(
            num_needed + num_forbidden,
            sample_limit as usize,
        ));
    }

    for ((real, ring), reused) in real_indices
        .iter()
        .zip(rings.iter_mut())
        .zip(reused_requests)
    {
        // Privacy: our own outputs are sampled like any other (see the doc
        // comment for why excluding them would be worse).
        while ring.len() < num_mixins_per_ring {
            let index = rng.random_range(0..sample_limit);
            if forbidden.insert(index) {
                ring.push(index);
            }
        }
        // Record the outcome. An existing entry keeps its first request; a new
        // one starts from the reused request, or from this ring if nothing was
        // reused.
        match ring_cache.entry(*real) {
            Entry::Occupied(mut entry) => {
                // A proposal does not change the mixins used in transactions:
                // forgetting a replacement that happens to be an output of ours
                // would give that output a fresh ring when it is spent later.
                if !for_proposal {
                    entry.get_mut().mixins = ring.clone();
                }
            }
            Entry::Vacant(entry) => {
                let first_request = reused.unwrap_or_else(|| {
                    core::iter::once(*real)
                        .chain(ring.iter().cloned())
                        .collect()
                });
                entry.insert(CachedInput {
                    first_request,
                    mixins: ring.clone(),
                });
            }
        }
    }

    let mut request_indices: Vec<u64> = real_indices
        .iter()
        .flat_map(|real| ring_cache[real].request())
        .collect();
    request_indices.sort_unstable();
    request_indices.dedup();

    Ok(RingSelection {
        mixins: rings,
        request_indices,
    })
}

#[cfg(test)]
mod test_select_mixin_indices {
    use super::*;
    use mc_util_test_helper::get_seeded_rng;

    const RING_SIZE: usize = 11;
    const NUM_MIXINS: usize = RING_SIZE - 1;
    const SAMPLE_LIMIT: u64 = 1000;
    /// `MAX_REQUEST_SIZE` of the fog ledger merkle proof service
    const FOG_LEDGER_MAX_REQUEST_SIZE: usize = 2000;

    fn select<T: CryptoRng>(
        real_indices: &[u64],
        ring_cache: &mut HashMap<u64, CachedInput>,
        rng: &mut T,
    ) -> RingSelection {
        select_with(real_indices, false, ring_cache, rng)
    }

    fn select_with<T: CryptoRng>(
        real_indices: &[u64],
        for_proposal: bool,
        ring_cache: &mut HashMap<u64, CachedInput>,
        rng: &mut T,
    ) -> RingSelection {
        let selection = select_mixin_indices(
            real_indices,
            for_proposal,
            ring_cache,
            NUM_MIXINS,
            SAMPLE_LIMIT,
            rng,
        )
        .expect("select_mixin_indices failed");
        assert_valid(real_indices, &selection.mixins);
        assert_request(real_indices, &selection, ring_cache);
        selection
    }

    /// A cache entry as it would look right after `real` was first used with
    /// these mixins
    fn entry(real: u64, mixins: &[u64]) -> CachedInput {
        CachedInput {
            first_request: core::iter::once(real)
                .chain(mixins.iter().cloned())
                .collect(),
            mixins: mixins.to_vec(),
        }
    }

    /// A cache entry for `real` whose ring was first `first_mixins` and whose
    /// mixins have since been replaced by `current_mixins`
    fn replaced_entry(real: u64, first_mixins: &[u64], current_mixins: &[u64]) -> CachedInput {
        CachedInput {
            mixins: current_mixins.to_vec(),
            ..entry(real, first_mixins)
        }
    }

    fn sorted<'a>(indices: impl IntoIterator<Item = &'a u64>) -> Vec<u64> {
        let mut sorted: Vec<u64> = indices.into_iter().cloned().collect();
        sorted.sort_unstable();
        sorted
    }

    fn is_subset<'a>(smaller: &[u64], larger: impl IntoIterator<Item = &'a u64>) -> bool {
        let larger: HashSet<u64> = larger.into_iter().cloned().collect();
        smaller.iter().all(|index| larger.contains(index))
    }

    /// The rings must be full, and all ring members (real and mixin) must be
    /// distinct.
    fn assert_valid(real_indices: &[u64], rings: &[Vec<u64>]) {
        assert_eq!(rings.len(), real_indices.len());
        let mut seen: HashSet<u64> = real_indices.iter().cloned().collect();
        for ring in rings {
            assert_eq!(ring.len(), NUM_MIXINS);
            for mixin in ring {
                assert!(*mixin < SAMPLE_LIMIT);
                assert!(seen.insert(*mixin), "index {mixin} used twice");
            }
        }
    }

    /// The request must hold, for every input, its first request and its
    /// mixins, nothing else, sorted and without duplicates.
    fn assert_request(
        real_indices: &[u64],
        selection: &RingSelection,
        cache: &HashMap<u64, CachedInput>,
    ) {
        let mut expected: Vec<u64> = Vec::new();
        for (real, mixins) in real_indices.iter().zip(&selection.mixins) {
            expected.push(*real);
            expected.extend(mixins);
            expected.extend(cache[real].request());
        }
        expected.sort_unstable();
        expected.dedup();
        assert_eq!(selection.request_indices, expected);
    }

    #[test]
    fn repeated_build_reuses_the_same_rings() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();
        let real = [7, 42, 500];

        let first = select(&real, &mut cache, &mut rng);
        // A new input's first request is its first ring
        for (real, mixins) in real.iter().zip(&first.mixins) {
            assert_eq!(cache[real], entry(*real, mixins));
        }
        assert_eq!(first.request_indices.len(), 3 * RING_SIZE);

        let second = select(&real, &mut cache, &mut rng);
        assert_eq!(second.mixins, first.mixins);
        assert_eq!(second.request_indices, first.request_indices);

        // A subset of the inputs, in a different order, still gets the same rings
        let third = select(&[500, 7], &mut cache, &mut rng);
        assert_eq!(
            third.mixins,
            vec![first.mixins[2].clone(), first.mixins[0].clone()]
        );

        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn new_input_gets_a_fresh_ring_without_disturbing_cached_ones() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        let first = select(&[7], &mut cache, &mut rng);
        let both = select(&[7, 42], &mut cache, &mut rng);
        assert_eq!(both.mixins[0], first.mixins[0]);
        assert_eq!(cache[&42], entry(42, &both.mixins[1]));
        assert_eq!(both.request_indices.len(), 2 * RING_SIZE);
    }

    #[test]
    fn changing_input_combinations_do_not_merge_histories() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        let first = select(&[7, 42], &mut cache, &mut rng);
        let second = select(&[42, 99], &mut cache, &mut rng);
        let third = select(&[99, 500], &mut cache, &mut rng);

        // An input keeps its ring whichever inputs it is built with
        assert_eq!(second.mixins[0], first.mixins[1]);
        assert_eq!(third.mixins[0], second.mixins[1]);

        // Inputs built together earlier are not dragged into later requests:
        // each input contributes exactly its own ring (see `assert_request`)
        assert_eq!(third.request_indices.len(), 2 * RING_SIZE);
        assert!(!third.request_indices.contains(&7));
        assert!(!third.request_indices.contains(&42));

        let alone = select(&[7], &mut cache, &mut rng);
        assert_eq!(alone.mixins[0], first.mixins[0]);
        assert_eq!(alone.request_indices.len(), RING_SIZE);
    }

    #[test]
    fn mixin_colliding_with_a_true_input_is_replaced() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        let first = select(&[7], &mut cache, &mut rng);
        // Pretend that 42, which we own, was sampled as a mixin of 7's ring
        let mut poisoned = first.mixins[0].clone();
        poisoned[3] = 42;
        let seeded = entry(7, &poisoned);
        cache.insert(7, seeded.clone());

        let selection = select(&[7, 42], &mut cache, &mut rng);

        // Only the colliding mixin was replaced: the other nine are kept, in
        // order, and the replacement is appended after them
        let kept: Vec<u64> = poisoned.iter().filter(|m| **m != 42).cloned().collect();
        assert_eq!(selection.mixins[0][..NUM_MIXINS - 1], kept[..]);
        assert_eq!(cache[&7].mixins, selection.mixins[0]);

        // The first request is untouched: 42 stays in it although it is no
        // longer a mixin, so later requests for 7 keep fetching it and the
        // operator cannot tell it apart from the other members
        assert_eq!(cache[&7].first_request, seeded.first_request);
        assert!(cache[&7].first_request.contains(&42));

        // 42 reused 7's request although every member of it was reserved, so
        // its ring in this transaction is fresh, but the ring it will show in
        // proposals comes from the reused request, which every later request
        // involving 42 contains.
        let reused = &cache[&42];
        assert_eq!(
            sorted(&reused.first_request),
            sorted(&cache[&7].first_request)
        );
        assert_eq!(reused.mixins, selection.mixins[1]);
        let sci_mixins = reused.sci_mixins(42, NUM_MIXINS);
        assert_eq!(sci_mixins.len(), NUM_MIXINS);
        assert!(is_subset(&sci_mixins, &reused.first_request));
        assert!(!sci_mixins.contains(&42));
        let proposal = select_with(&[42], true, &mut cache, &mut rng);
        assert_eq!(proposal.mixins[0], sci_mixins);
        assert!(is_subset(&sci_mixins, &proposal.request_indices));
    }

    #[test]
    fn owned_output_found_in_an_earlier_request_reuses_it() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        let first = select(&[7], &mut cache, &mut rng);
        // Pretend that 42, which we own, was sampled as a mixin of 7's ring
        let mut poisoned = first.mixins[0].clone();
        poisoned[3] = 42;
        cache.insert(7, entry(7, &poisoned));
        let request_of_7 = cache[&7].request();
        // The operator has now seen 42 among the members of 7's ring
        let parent = select(&[7], &mut cache, &mut rng);

        // Spending 42 must not give it a fresh ring, which would share only 42
        // with 7's request and so single it out. Instead its ring is the rest
        // of 7's request, its first request is all of it, and the network
        // request is identical to the one made for 7
        let selection = select(&[42], &mut cache, &mut rng);
        let expected: Vec<u64> = request_of_7.iter().cloned().filter(|i| *i != 42).collect();
        assert_eq!(sorted(&selection.mixins[0]), sorted(&expected));
        assert_eq!(sorted(&cache[&42].first_request), sorted(&request_of_7));
        assert_eq!(cache[&42].mixins, selection.mixins[0]);
        assert_eq!(selection.request_indices, parent.request_indices);
        // 7's own entry is untouched
        assert_eq!(cache[&7], entry(7, &poisoned));

        // And a repeated build of 42 is stable
        let again = select(&[42], &mut cache, &mut rng);
        assert_eq!(again.mixins, selection.mixins);
        assert_eq!(again.request_indices, selection.request_indices);
    }

    #[test]
    fn owned_output_found_among_replaced_mixins_reuses_the_whole_request() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // 7's ring was first {7} + 100..110 and has since been fully replaced
        // by 200..210, with 42 (which we own) among the replacements.
        let first_mixins: Vec<u64> = (100..110).collect();
        let mut current_mixins: Vec<u64> = (200..210).collect();
        current_mixins[3] = 42;
        cache.insert(7, replaced_entry(7, &first_mixins, &current_mixins));
        let request_of_7 = cache[&7].request();
        let parent = select(&[7], &mut cache, &mut rng);
        assert_eq!(parent.request_indices.len(), 2 * RING_SIZE - 1);

        let selection = select(&[42], &mut cache, &mut rng);
        // 42's first request is all of 7's request, and its ring a part of it
        assert_eq!(sorted(&cache[&42].first_request), sorted(&request_of_7));
        let mixins = &selection.mixins[0];
        assert!(is_subset(mixins, &request_of_7));
        assert!(!mixins.contains(&42));
        // And the request is indistinguishable from a retry of 7
        assert_eq!(selection.request_indices, parent.request_indices);

        // The ring shown in proposals is retained even after 42's mixins are
        // replaced
        let sci_mixins = cache[&42].sci_mixins(42, NUM_MIXINS);
        cache.get_mut(&42).unwrap().mixins = (300..310).collect();
        let proposal = select_with(&[42], true, &mut cache, &mut rng);
        assert_eq!(proposal.mixins[0], sci_mixins);
    }

    #[test]
    fn reused_ring_is_a_random_choice() {
        let mut rng = get_seeded_rng();

        // Repeated reuses of the same request (one index larger than a ring)
        // do not always drop the same member, so a counterparty who sees the
        // earlier ring and the reused one cannot tell which member is the new
        // real input.
        let first_mixins: Vec<u64> = (100..110).collect();
        let mut current_mixins: Vec<u64> = first_mixins.clone();
        current_mixins[0] = 42;
        let mut dropped: HashSet<u64> = HashSet::default();
        for _ in 0..50 {
            let mut cache = HashMap::default();
            cache.insert(7, replaced_entry(7, &first_mixins, &current_mixins));
            let selection = select(&[42], &mut cache, &mut rng);
            let candidates: Vec<u64> = cache[&42]
                .first_request
                .iter()
                .cloned()
                .filter(|i| *i != 42 && !selection.mixins[0].contains(i))
                .collect();
            assert_eq!(candidates.len(), 1);
            dropped.insert(candidates[0]);
        }
        assert!(dropped.len() > 1);
    }

    #[test]
    fn oversized_requests_are_skipped_in_favour_of_a_smaller_one() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // 42 is in the requests of both 5 and 9. 5's is too large to reuse,
        // 9's is not, so 9's is reused although 5 < 9.
        let big: Vec<u64> = [5, 42].into_iter().chain(100..120).collect();
        cache.insert(
            5,
            CachedInput {
                first_request: big,
                mixins: (200..210).collect(),
            },
        );
        let mut small: Vec<u64> = (300..310).collect();
        small[4] = 42;
        cache.insert(9, entry(9, &small));

        let selection = select(&[42], &mut cache, &mut rng);
        assert_eq!(
            sorted(&cache[&42].first_request),
            sorted(&cache[&9].first_request)
        );
        assert_eq!(selection.request_indices.len(), RING_SIZE);
    }

    #[test]
    fn shared_mixin_between_cached_rings_is_replaced() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        let ring_a = select(&[7], &mut cache, &mut rng).mixins[0].clone();
        let mut ring_b = select(&[42], &mut cache, &mut rng).mixins[0].clone();
        assert_valid(&[7, 42], &[ring_a.clone(), ring_b.clone()]);
        // Pretend the two rings happened to share a mixin
        ring_b[0] = ring_a[5];
        cache.insert(42, entry(42, &ring_b));

        let selection = select(&[7, 42], &mut cache, &mut rng);
        // 7 comes first, so its ring is kept whole and 42's ring gives up the
        // shared mixin: its other nine stay in order and a fresh one is appended
        assert_eq!(selection.mixins[0], ring_a);
        assert_eq!(selection.mixins[1][..NUM_MIXINS - 1], ring_b[1..]);
        // The replacement adds one index, the shared one is counted once
        assert_eq!(selection.request_indices.len(), 2 * RING_SIZE);
    }

    /// An input loses mixins to collisions in an intermediate (abandoned) build
    /// with other inputs. Without the first request being sent along, its
    /// next solo request would share only the input itself with its first
    /// solo request.
    #[test]
    fn replaced_mixins_do_not_shrink_the_intersection_of_requests() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // 42's and 99's rings each share one mixin with 7's ring
        let ring_of_7: Vec<u64> = (100..110).collect();
        let mut ring_of_42: Vec<u64> = (200..210).collect();
        ring_of_42[0] = ring_of_7[0];
        let mut ring_of_99: Vec<u64> = (300..310).collect();
        ring_of_99[0] = ring_of_7[1];
        cache.insert(7, entry(7, &ring_of_7));
        cache.insert(42, entry(42, &ring_of_42));
        cache.insert(99, entry(99, &ring_of_99));

        // 1. 7 alone
        let first = select(&[7], &mut cache, &mut rng);
        assert_eq!(first.mixins[0], ring_of_7);

        // 2. 42, 99 and 7 together: 7 comes last, so it loses the two shared mixins.
        //    This build is abandoned.
        let joint = select(&[42, 99, 7], &mut cache, &mut rng);
        assert_eq!(joint.mixins[2][..NUM_MIXINS - 2], ring_of_7[2..]);
        assert!(is_subset(&first.request_indices, &joint.request_indices));

        // 3. 7 alone again: the changed ring, plus the first request
        let third = select(&[7], &mut cache, &mut rng);
        assert_eq!(third.mixins[0], joint.mixins[2]);
        assert!(is_subset(&first.request_indices, &third.request_indices));
        assert_eq!(third.request_indices.len(), RING_SIZE + 2);
    }

    #[test]
    fn request_size_stays_within_the_fog_ledger_limit() {
        use mc_transaction_core::constants::{MAX_INPUTS, RING_SIZE as NETWORK_RING_SIZE};
        assert_eq!(RING_SIZE, NETWORK_RING_SIZE);
        assert!(
            (MAX_INPUTS as usize) * (MAX_REUSED_REQUEST_RINGS * RING_SIZE + RING_SIZE - 1)
                < FOG_LEDGER_MAX_REQUEST_SIZE
        );

        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // Build the worst case: the maximum number of inputs, each with the
        // largest first request a reuse allows (22 indices) and with every one
        // of its 10 mixins replaced since, so that none of them is in the first
        // request any more. Each input then contributes 22 + 10 = 32 distinct
        // indices. The ranges are chosen so that no two inputs overlap either.
        let max_first_request = MAX_REUSED_REQUEST_RINGS * RING_SIZE;
        let real: Vec<u64> = (0..MAX_INPUTS).collect();
        for input in &real {
            let start = 100 + (max_first_request as u64 - 1) * input;
            let first_request: Vec<u64> = core::iter::once(*input)
                .chain(start..start + max_first_request as u64 - 1)
                .collect();
            let mixins: Vec<u64> = (800 + 10 * input..810 + 10 * input).collect();
            cache.insert(
                *input,
                CachedInput {
                    first_request,
                    mixins,
                },
            );
        }

        let selection = select(&real, &mut cache, &mut rng);
        assert_eq!(
            selection.request_indices.len(),
            (MAX_INPUTS as usize) * (max_first_request + NUM_MIXINS)
        );
        assert!(selection.request_indices.len() < FOG_LEDGER_MAX_REQUEST_SIZE);
    }

    #[test]
    fn oversized_requests_are_not_reused() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();
        let max_first_request = MAX_REUSED_REQUEST_RINGS * RING_SIZE;

        // 7's first request is itself a reused one, as large as allowed, and
        // 42 (which we own) is in it.
        let first_request: Vec<u64> = [7, 42]
            .into_iter()
            .chain(100..100 + max_first_request as u64 - 2)
            .collect();
        assert_eq!(first_request.len(), max_first_request);

        // With 7's mixins inside it, 7's request is exactly at the limit:
        // reused
        cache.insert(
            7,
            CachedInput {
                first_request: first_request.clone(),
                mixins: first_request[1..RING_SIZE].to_vec(),
            },
        );
        let reused = select(&[42], &mut cache, &mut rng);
        assert_eq!(sorted(&cache[&42].first_request), sorted(&first_request));
        assert_eq!(reused.request_indices.len(), max_first_request);

        // With 7's mixins replaced by ones outside it, 7's request is over the
        // limit: 42 gets a fresh ring instead
        cache.remove(&42);
        cache.insert(
            7,
            CachedInput {
                first_request: first_request.clone(),
                mixins: (500..510).collect(),
            },
        );
        let fresh = select(&[42], &mut cache, &mut rng);
        assert_eq!(cache[&42], entry(42, &fresh.mixins[0]));
        assert_eq!(fresh.request_indices.len(), RING_SIZE);
    }

    #[test]
    fn proposal_rings_do_not_change() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // 7's ring was first {7} + 100..110 and has since been fully replaced,
        // with 42 (which we own) among the replacements
        let first_mixins: Vec<u64> = (100..110).collect();
        let mut current_mixins: Vec<u64> = (200..210).collect();
        current_mixins[3] = 42;
        cache.insert(7, replaced_entry(7, &first_mixins, &current_mixins));

        // An ordinary build uses the current mixins, a proposal the first
        // ring; both requests hold the first request and the current mixins
        let ordinary = select(&[7], &mut cache, &mut rng);
        assert_eq!(ordinary.mixins[0], current_mixins);
        let proposal = select_with(&[7], true, &mut cache, &mut rng);
        assert_eq!(proposal.mixins[0], first_mixins);
        assert!(is_subset(&current_mixins, &proposal.request_indices));
        // The proposal did not make 7 forget its current mixins, so 42 is
        // still found there when it is spent
        assert_eq!(cache[&7].mixins, current_mixins);
        let request_of_7 = cache[&7].request();
        let reused = select(&[42], &mut cache, &mut rng);
        assert_eq!(sorted(&cache[&42].first_request), sorted(&request_of_7));
        assert_eq!(sorted(&reused.request_indices), sorted(&request_of_7));
        assert!(is_subset(
            &cache[&7].first_request,
            &ordinary.request_indices
        ));
        assert!(is_subset(
            &cache[&7].first_request,
            &proposal.request_indices
        ));

        // A new input in a proposal is sampled like any other, and stays the
        // same in later proposals
        let fresh = select_with(&[99], true, &mut cache, &mut rng);
        assert_eq!(cache[&99], entry(99, &fresh.mixins[0]));
        let again = select_with(&[99], true, &mut cache, &mut rng);
        assert_eq!(again.mixins, fresh.mixins);
    }

    #[test]
    fn insufficient_tx_outs_is_an_error_not_a_hang() {
        let mut rng = get_seeded_rng();
        let mut cache = HashMap::default();

        // Needs 10 mixins from 0..11 minus the input itself: exactly enough
        let selection = select_mixin_indices(&[1], false, &mut cache, NUM_MIXINS, 11, &mut rng)
            .expect("exactly enough tx outs");
        let mut mixins = selection.mixins[0].clone();
        mixins.sort();
        assert_eq!(mixins, vec![0, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        // One fewer is an error
        let mut cache = HashMap::default();
        let res = select_mixin_indices(&[1], false, &mut cache, NUM_MIXINS, 10, &mut rng);
        assert!(matches!(
            res,
            Err(Error::InsufficientTxOutsInBlockchain(11, 10))
        ));
        assert!(cache.is_empty());
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
fn build_transaction_helper<T: CryptoRng>(
    block_version: BlockVersion,
    fee_map: FeeMap,
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

    let mut tx_builder = TransactionBuilder::new(
        block_version,
        Amount::new(fee, amount.token_id),
        fog_resolver,
    )?;

    tx_builder.set_fee_map(fee_map);

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

    // Use the RTHMemoBuilder
    // Note: Memos are disabled if we target an older block version
    let mut memo_builder = RTHMemoBuilder::default();
    memo_builder.set_sender_credential(SenderMemoCredential::from(source_account_key));
    memo_builder.enable_destination_memo();
    Ok(tx_builder.build(ring_signer, memo_builder, rng)?)
}

fn add_inputs_to_tx_builder<FPR: FogPubkeyResolver>(
    tx_builder: &mut TransactionBuilder<FPR>,
    inputs: Vec<(OwnedTxOut, TxOutMembershipProof)>,
    rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
    source_account_key: &AccountKey,
) -> Result<()> {
    assert_eq!(
        inputs.len(),
        rings.len(),
        "Each input must have a corresponding ring."
    );

    // Unzip each vec of tuples into a tuple of vecs.
    let rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
        .into_iter()
        .map(|tuples| tuples.into_iter().unzip())
        .collect();

    // Inputs and rings are in the same order: the ring of each input is the
    // one chosen for it (and remembered in the ring cache), not another's.
    for ((input_txo, input_proof), (ring, membership_proofs)) in
        inputs.into_iter().zip(rings_and_proofs)
    {
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
// of get_inputs_and_rings, and the account key which it uses to derive the
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
    use mc_account_keys::DEFAULT_SUBADDRESS_INDEX;
    use mc_common::logger::test_with_logger;
    use mc_crypto_keys::RistrettoPublic;
    use mc_fog_report_validation::{FogPubkeyError, FullyValidatedFogPubkey};
    use mc_fog_types::view::{FogTxOut, FogTxOutMetadata, TxOutRecord};
    use mc_transaction_core::{
        constants::MILLIMOB_TO_PICOMOB, onetime_keys::recover_public_subaddress_spend_key,
        tokens::Mob, Token,
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
                FeeMap::default(),
                inputs,
                rings_and_membership_proofs,
                amount_to_send,
                &sender_account_key,
                &recipient_account_key.default_subaddress(),
                super::BlockIndex::MAX,
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
