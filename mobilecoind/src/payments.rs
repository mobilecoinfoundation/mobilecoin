// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Construct and submit transactions to the validator network.

use crate::{database::Database, error::Error, monitor_store::MonitorId, utxo_store::UnspentTxOut};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_blockchain_types::{BlockIndex, BlockVersion};
use mc_common::{
    logger::{log, o, Logger},
    HashMap, HashSet,
};
use mc_connection::{
    BlockInfo, BlockchainConnection, ConnectionManager, RetryableUserTxConnection, UserTxConnection,
};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_transaction_builder::{
    InputCredentials, MemoBuilder, ReservedSubaddresses, TransactionBuilder, TxOutContext,
};
use mc_transaction_core::{
    constants::{MAX_INPUTS, MILLIMOB_TO_PICOMOB, RING_SIZE},
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, FeeMap, TokenId,
};
use mc_transaction_extra::TxOutConfirmationNumber;
use mc_util_uri::FogUri;
use rand::Rng;
use std::{
    cmp::{max, Reverse},
    iter::empty,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Default number of blocks used for calculating transaction tombstone block
/// number.
// TODO support for making this configurable
pub const DEFAULT_NEW_TX_BLOCK_ATTEMPTS: u64 = 50;

/// Default ring size
pub const DEFAULT_RING_SIZE: usize = RING_SIZE;

/// The original hard-coded 10mMOB fee, used as a fallback when calls to
/// consensus fail or we have no peers.
const FALLBACK_FEE: u64 = 10 * MILLIMOB_TO_PICOMOB;

/// An outlay - the API representation of a desired transaction output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outlay {
    /// Value being sent.
    pub value: u64,

    /// Destination.
    pub receiver: PublicAddress,
}

/// A single pending transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxProposal {
    /// UTXOs used as inputs for this transaction.
    pub utxos: Vec<UnspentTxOut>,

    /// Destinations the transaction is being sent to.
    pub outlays: Vec<Outlay>,

    /// The actual transaction.
    pub tx: Tx,

    /// A map of outlay index -> TxOut index in the Tx object.
    /// This is needed to map recipients to their respective TxOuts.
    pub outlay_index_to_tx_out_index: HashMap<usize, usize>,

    /// A list of the confirmation numbers, in the same order
    /// as the outlays.
    pub outlay_confirmation_numbers: Vec<TxOutConfirmationNumber>,
}

impl TxProposal {
    pub fn fee(&self) -> u64 {
        self.tx.prefix.fee
    }
}

pub struct TransactionsManager<
    T: BlockchainConnection + UserTxConnection + 'static,
    FPR: FogPubkeyResolver,
> {
    /// Ledger database.
    ledger_db: LedgerDB,

    /// mobilecoind database.
    mobilecoind_db: Database,

    /// Peer manager, for communicating with validator nodes.
    peer_manager: ConnectionManager<T>,

    /// Monotonically increasing counter. This is used for node round-robin
    /// selection.
    submit_node_offset: Arc<AtomicUsize>,

    /// Fog resolver maker, used when constructing outputs to fog recipients.
    /// This is abstracted because in tests, we don't want to form grpc
    /// connections to fog
    fog_resolver_factory: Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync>,

    /// Logger.
    logger: Logger,
}

impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver> Clone
    for TransactionsManager<T, FPR>
{
    fn clone(&self) -> Self {
        Self {
            ledger_db: self.ledger_db.clone(),
            mobilecoind_db: self.mobilecoind_db.clone(),
            peer_manager: self.peer_manager.clone(),
            submit_node_offset: self.submit_node_offset.clone(),
            fog_resolver_factory: self.fog_resolver_factory.clone(),
            logger: self.logger.clone(),
        }
    }
}

/// Get the most common BlockInfo out of a list of BlockInfos.
/// The assumption is that in the majority of cases, all the BlockInfos
/// would be the same. They will only differ during a network upgrade
/// or if a node is left running with an old configuration.
fn get_majority_block_info(block_infos: &[BlockInfo]) -> Option<BlockInfo> {
    let mut block_info_counts = HashMap::default();
    for block_info in block_infos {
        *block_info_counts.entry(block_info).or_insert(0) += 1;
    }

    block_info_counts
        .into_iter()
        .max_by_key(|(_block_info, count)| *count)
        .map(|(block_info, _count)| block_info.clone())
}

impl<T: BlockchainConnection + UserTxConnection + 'static, FPR: FogPubkeyResolver>
    TransactionsManager<T, FPR>
{
    pub fn new(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        peer_manager: ConnectionManager<T>,
        fog_resolver_factory: Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync>,
        logger: Logger,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            ledger_db,
            mobilecoind_db,
            peer_manager,
            submit_node_offset: Arc::new(AtomicUsize::new(rng.next_u64() as usize)),
            fog_resolver_factory,
            logger,
        }
    }

    // Gets the network fee and block_version, unless opt_fee is nonzero.
    // If opt fee is nonzero then we use local ledger block version and this fee,
    // and don't make a network call
    fn get_network_fee_and_block_version(
        &self,
        token_id: TokenId,
        opt_fee: u64,
        last_block_info: &BlockInfo,
    ) -> Result<(u64, u32), Error> {
        // Figure out the block_version and fee, taking into account if opt_fee is
        // nonzero
        let candidate_block_version = self.ledger_db.get_latest_block()?.version;
        Ok(if opt_fee != 0 {
            (opt_fee, candidate_block_version)
        } else {
            let fee = last_block_info
                .minimum_fee_or_none(&token_id)
                .unwrap_or(FALLBACK_FEE);
            let block_version = max(
                candidate_block_version,
                last_block_info.network_block_version,
            );
            (fee, block_version)
        })
    }

    // A helper for figuring ou the minimum fee, fee map and block version from a
    // list of BlockInfo objects.
    // # Arguments
    // * `last_block_info` - The last block info we have from each node
    // * `token_id` - The token id we are interested in
    // * `opt_fee` - If nonzero, use this fee instead of the network fee
    fn get_fee_info_and_block_version(
        &self,
        last_block_infos: &[BlockInfo],
        token_id: TokenId,
        opt_fee: u64,
    ) -> Result<(u64, FeeMap, BlockVersion), Error> {
        let last_block_info = get_majority_block_info(last_block_infos)
            .ok_or_else(|| Error::TxBuild("No block info available".into()))?;

        let (fee, block_version) =
            self.get_network_fee_and_block_version(token_id, opt_fee, &last_block_info)?;

        let fee_map = FeeMap::try_from(last_block_info.minimum_fees)?;

        let block_version =
            BlockVersion::try_from(block_version).map_err(|err| Error::TxBuild(err.to_string()))?;

        Ok((fee, fee_map, block_version))
    }

    /// Create a TxProposal.
    ///
    /// # Arguments
    /// * `sender_monitor_id` - Indicates the the account key needed to spend
    ///   the txo's.
    /// * `token_id` - The token id to transact in.
    /// * `change_subaddress` - Recipient of any change.
    /// * `inputs` - UTXOs that will be spent by the transaction.
    /// * `outlays` - Output amounts and recipients.
    /// * `last_block_infos` - Last block info responses from the network, for
    ///   determining fees. This should normally come from polling_network_state
    /// * `opt_fee` - Transaction fee in picoMOB. If zero, defaults to MIN_FEE.
    /// * `opt_tombstone` - Tombstone block. If zero, sets to default.
    /// * `opt_memo_builder` - Optional memo builder to use instead of the
    ///   default one (EmptyMemoBuilder).
    pub fn build_transaction(
        &self,
        sender_monitor_id: &MonitorId,
        token_id: TokenId,
        change_subaddress: u64,
        inputs: &[UnspentTxOut],
        outlays: &[Outlay],
        last_block_infos: &[BlockInfo],
        opt_fee: u64,
        opt_tombstone: u64,
        opt_memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(o!("sender_monitor_id" => sender_monitor_id.to_string(), "outlays" => format!("{outlays:?}")));
        log::trace!(logger, "Building pending transaction...");

        // All inputs must be of the correct token id.
        if inputs.iter().any(|utxo| utxo.token_id != *token_id) {
            return Err(Error::InvalidArgument(
                "inputs".to_string(),
                format!("All inputs must be of token_id {token_id}"),
            ));
        }

        // Must have at least one output
        if outlays.is_empty() {
            return Err(Error::TxBuild("Must have at least one destination".into()));
        }

        // Get sender monitor data.
        let sender_monitor_data = self.mobilecoind_db.get_monitor_data(sender_monitor_id)?;

        // Figure out total amount of transaction (excluding fee).
        let total_value: u64 = outlays.iter().map(|outlay| outlay.value).sum();
        log::trace!(
            logger,
            "Total transaction value excluding fees: {}",
            total_value
        );

        // Figure out the block version, fee and minimum fee map.
        let (fee, fee_map, block_version) =
            self.get_fee_info_and_block_version(last_block_infos, token_id, opt_fee)?;

        // Select the UTXOs to be used for this transaction.
        let selected_utxos =
            Self::select_utxos_for_value(token_id, inputs, total_value + fee, MAX_INPUTS as usize)?;
        log::trace!(
            logger,
            "Selected {} utxos ({:?})",
            selected_utxos.len(),
            selected_utxos,
        );

        // The selected_utxos with corresponding proofs of membership.
        let selected_utxos_with_proofs: Vec<(UnspentTxOut, TxOutMembershipProof)> = {
            let outputs: Vec<TxOut> = selected_utxos
                .iter()
                .map(|utxo| utxo.tx_out.clone())
                .collect();
            let proofs = self.get_membership_proofs(&outputs)?;

            selected_utxos.into_iter().zip(proofs.into_iter()).collect()
        };
        log::trace!(logger, "Got membership proofs");

        // A ring of mixins for each UTXO.
        let rings = {
            let excluded_tx_out_indices: Vec<u64> = selected_utxos_with_proofs
                .iter()
                .map(|(_, proof)| proof.index)
                .collect();

            self.get_rings(
                DEFAULT_RING_SIZE, // TODO configurable ring size
                selected_utxos_with_proofs.len(),
                &excluded_tx_out_indices,
            )?
        };
        log::trace!(logger, "Got {} rings", rings.len());

        // Come up with tombstone block.
        let tombstone_block = if opt_tombstone > 0 {
            opt_tombstone
        } else {
            let num_blocks_in_ledger = self.ledger_db.num_blocks()?;
            num_blocks_in_ledger + DEFAULT_NEW_TX_BLOCK_ATTEMPTS
        };
        log::trace!(logger, "Tombstone block set to {}", tombstone_block);

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let tx_proposal = Self::build_tx_proposal(
            &selected_utxos_with_proofs,
            rings,
            block_version,
            token_id,
            fee,
            &sender_monitor_data.account_key,
            change_subaddress,
            outlays,
            tombstone_block,
            &self.fog_resolver_factory,
            opt_memo_builder,
            fee_map,
            &mut rng,
            &self.logger,
        )?;
        log::trace!(logger, "Tx constructed, hash={}", tx_proposal.tx.tx_hash());

        Ok(tx_proposal)
    }

    /// Create a TxProposal that attempts to merge multiple UTXOs into a single
    /// larger UTXO.
    ///
    /// # Arguments
    /// * `monitor_id` - Monitor ID of the inputs to spend.
    /// * `subaddress_index` - Subaddress of the inputs to spend.
    /// * `token_id` - Token id to transact in.
    /// * `last_block_infos` - Last block info responses from the network, for
    ///   determining fees. This should normally come from polling_network_state
    /// * `opt_fee` - Optional fee to use. If zero, we will attempt to query the
    ///   network for fee information.
    pub fn generate_optimization_tx(
        &self,
        monitor_id: &MonitorId,
        subaddress_index: u64,
        token_id: TokenId,
        last_block_infos: &[BlockInfo],
        opt_fee: u64,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(
            o!("monitor_id" => monitor_id.to_string(), "subaddress_index" => subaddress_index),
        );
        log::trace!(logger, "Generating optimization transaction...");

        // Get monitor data.
        let monitor_data = self.mobilecoind_db.get_monitor_data(monitor_id)?;

        let num_blocks_in_ledger = self.ledger_db.num_blocks()?;

        // Figure out the block version, fee and minimum fee map.
        let (fee, fee_map, block_version) =
            self.get_fee_info_and_block_version(last_block_infos, token_id, opt_fee)?;

        // Select UTXOs that will be spent by this transaction.
        let selected_utxos = {
            let inputs = self
                .mobilecoind_db
                .get_utxos_for_subaddress(monitor_id, subaddress_index)?;
            Self::select_utxos_for_optimization(
                num_blocks_in_ledger,
                &inputs,
                MAX_INPUTS as usize,
                token_id,
                fee,
            )?
        };

        log::trace!(
            logger,
            "Selected {} utxos: {:?}",
            selected_utxos.len(),
            selected_utxos
        );

        // Figure out total amount of transaction (excluding fee).
        let total_value: u64 = selected_utxos.iter().map(|utxo| utxo.value).sum();
        log::trace!(
            logger,
            "Total transaction value excluding fees: {}",
            total_value
        );

        // The selected_utxos with corresponding proofs of membership.
        let selected_utxos_with_proofs: Vec<(UnspentTxOut, TxOutMembershipProof)> = {
            let outputs: Vec<TxOut> = selected_utxos
                .iter()
                .map(|utxo| utxo.tx_out.clone())
                .collect();
            let proofs = self.get_membership_proofs(&outputs)?;

            selected_utxos.into_iter().zip(proofs.into_iter()).collect()
        };
        log::trace!(logger, "Got membership proofs");

        // A ring of mixins for each selected UTXO.
        let rings = {
            let excluded_tx_out_indices: Vec<u64> = selected_utxos_with_proofs
                .iter()
                .map(|(_, proof)| proof.index)
                .collect();

            self.get_rings(
                DEFAULT_RING_SIZE, // TODO configurable ring size
                selected_utxos_with_proofs.len(),
                &excluded_tx_out_indices,
            )?
        };
        log::trace!(logger, "Got {} rings", rings.len());

        // Come up with tombstone block.
        let tombstone_block = num_blocks_in_ledger + DEFAULT_NEW_TX_BLOCK_ATTEMPTS;
        log::trace!(logger, "Tombstone block set to {}", tombstone_block);

        // We are paying ourselves the entire amount.
        let outlays = vec![Outlay {
            receiver: monitor_data.account_key.subaddress(subaddress_index),
            value: total_value - fee,
        }];

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let tx_proposal = Self::build_tx_proposal(
            &selected_utxos_with_proofs,
            rings,
            block_version,
            token_id,
            fee,
            &monitor_data.account_key,
            subaddress_index,
            &outlays,
            tombstone_block,
            &self.fog_resolver_factory,
            None,
            fee_map,
            &mut rng,
            &self.logger,
        )?;
        log::trace!(
            logger,
            "Optimization tx constructed, hash={}",
            tx_proposal.tx.tx_hash()
        );

        Ok(tx_proposal)
    }

    /// Create a TxProposal that sends the total value of all inputs minus the
    /// fee to a single receiver. (ignoring inputs with wrong token id)
    ///
    /// # Arguments
    /// * `account_key` - Account key that owns the inputs.
    /// * `token_id` - The token id to transact in.
    /// * `inputs` - UTXOs that will be spent by the transaction.
    /// * `receiver` - The single receiver of the transaction's outputs.
    /// * `last_block_infos` - Last block info responses from the network, for
    ///   determining fees. This should normally come from polling_network_state
    /// * `opt_fee` - Transaction fee. If zero, defaults to the highest fee set
    ///   by configured consensus nodes, or the hard-coded FALLBACK_FEE.
    pub fn generate_tx_from_tx_list(
        &self,
        account_key: &AccountKey,
        token_id: TokenId,
        inputs: &[UnspentTxOut],
        receiver: &PublicAddress,
        last_block_infos: &[BlockInfo],
        opt_fee: u64,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(o!("receiver" => receiver.to_string()));
        log::trace!(logger, "Generating txo list transaction...");

        // All inputs must be of the correct token id.
        if inputs.iter().any(|utxo| utxo.token_id != *token_id) {
            return Err(Error::InvalidArgument(
                "inputs".to_string(),
                format!("All inputs must be of token_id {token_id}"),
            ));
        }

        // Figure out the block version, fee and minimum fee map.
        let (fee, fee_map, block_version) =
            self.get_fee_info_and_block_version(last_block_infos, token_id, opt_fee)?;

        // All inputs are to be spent, except those with wrong token id
        let total_value: u64 = inputs.iter().map(|utxo| utxo.value).sum();

        if total_value < fee {
            return Err(Error::InsufficientFunds);
        }

        log::trace!(
            logger,
            "Total transaction value excluding fees: {}",
            total_value - fee
        );

        // The inputs with corresponding proofs of membership.
        let inputs_with_proofs: Vec<(UnspentTxOut, TxOutMembershipProof)> = {
            let tx_outs: Vec<TxOut> = inputs.iter().map(|utxo| utxo.tx_out.clone()).collect();
            let proofs = self.get_membership_proofs(&tx_outs)?;
            inputs.iter().cloned().zip(proofs.into_iter()).collect()
        };
        log::trace!(logger, "Got membership proofs");

        // The index of each input in the ledger.
        let input_indices: Vec<u64> = inputs_with_proofs
            .iter()
            .map(|(_, membership_proof)| membership_proof.index)
            .collect();

        let rings = self.get_rings(DEFAULT_RING_SIZE, inputs_with_proofs.len(), &input_indices)?;
        log::trace!(logger, "Got {} rings", rings.len());

        // Come up with tombstone block.
        let tombstone_block = self.ledger_db.num_blocks()? + DEFAULT_NEW_TX_BLOCK_ATTEMPTS;
        log::trace!(logger, "Tombstone block set to {}", tombstone_block);

        // The entire value goes to receiver
        let outlays = vec![Outlay {
            receiver: receiver.clone(),
            value: total_value - fee,
        }];

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let tx_proposal = Self::build_tx_proposal(
            &inputs_with_proofs,
            rings,
            block_version,
            token_id,
            fee,
            account_key,
            0,
            &outlays,
            tombstone_block,
            &self.fog_resolver_factory,
            None,
            fee_map,
            &mut rng,
            &self.logger,
        )?;
        log::trace!(
            logger,
            "Tx list tx constructed, hash={}",
            tx_proposal.tx.tx_hash()
        );

        Ok(tx_proposal)
    }

    /// Submit a previously built tx proposal to the network.
    pub fn submit_tx_proposal(&self, tx_proposal: &TxProposal) -> Result<u64, Error> {
        // Pick a peer to submit to.
        let responder_ids = self.peer_manager.responder_ids();
        if responder_ids.is_empty() {
            return Err(Error::NoPeersConfigured);
        }

        let idx = self.submit_node_offset.fetch_add(1, Ordering::SeqCst);
        let responder_id = &responder_ids[idx % responder_ids.len()];

        // Try and submit.
        let block_height = self
            .peer_manager
            .conn(responder_id)
            .ok_or(Error::NodeNotFound)?
            .propose_tx(&tx_proposal.tx, empty())
            .map_err(Error::from)?;

        log::info!(
            self.logger,
            "Tx {} submitted at block height {}",
            tx_proposal.tx,
            block_height
        );

        // Successfully submitted.
        Ok(block_height)
    }

    /// Returns a subset of UTXOs totalling at least the given amount.
    // TODO: This method should take attempted_spend_height into account.
    fn select_utxos_for_value(
        token_id: TokenId,
        utxos: &[UnspentTxOut],
        value: u64,
        max_inputs: usize,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        // Sort the utxos in descending order by value.
        let mut sorted_utxos: Vec<UnspentTxOut> = utxos
            .iter()
            .filter(|utxo| utxo.token_id == token_id)
            .cloned()
            .collect();
        sorted_utxos.sort_by_key(|utxo| Reverse(utxo.value));

        // The maximum spendable is limited by the maximal number of inputs we can use.
        let max_spendable_amount = sorted_utxos
            .iter()
            .take(max_inputs)
            .map(|utxo| utxo.value)
            .sum();
        if value > max_spendable_amount {
            // See if we merged the UTXOs we would be able to spend this amount.
            let total_utxos_value: u64 = sorted_utxos.iter().map(|utxo| utxo.value).sum();
            if total_utxos_value >= value {
                return Err(Error::InsufficientFundsFragmentedUtxos);
            } else {
                return Err(Error::InsufficientFunds);
            }
        }

        // Choose utxos to spend.
        let mut selected_utxos: Vec<UnspentTxOut> = Vec::new();
        loop {
            let total: u64 = selected_utxos.iter().map(|utxo| utxo.value).sum();
            if total >= value {
                break;
            }

            // Grab the next (smallest utxo)
            let next_utxo = sorted_utxos.pop().ok_or(Error::InsufficientFunds)?;
            selected_utxos.push(next_utxo.clone());

            // Cap at maximum allowed inputs.
            if selected_utxos.len() > max_inputs {
                // Remove the lowest utxo.
                selected_utxos.remove(0);
            }
        }

        // Sanity.
        assert!(!selected_utxos.is_empty());
        assert!(selected_utxos.len() <= max_inputs);

        // Return selected utxos.
        Ok(selected_utxos)
    }

    /// Select UTXOs for optimization. The current strategy is to to attempt to
    /// add the maximum number of small UTXOs into the biggest one, which is
    /// the one most likely to be used when spending. The assumption is that
    /// if we maintain it as the biggest, we're less likely to need multiple
    /// UTXOs in future transactions.
    /// 1) Filter out UTXOs which we believe are currently still pending/at an
    /// unknown state. 2) Sort remaining UTXOs in ascending order (by their
    /// value). 3) Grab the largest available UTXO, and MAX_INPUTS-1
    /// smallest available UTXOs. 4) If the sum of the smallest available
    /// UTXOs > fee, we would be able to increase our largest    UTXO and
    /// we're done. If not, try again without the smallest UTXO.
    ///
    /// Returns selected UTXOs
    fn select_utxos_for_optimization(
        num_blocks_in_ledger: u64,
        inputs: &[UnspentTxOut],
        max_inputs: usize,
        token_id: TokenId,
        fee: u64,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        if max_inputs < 2 {
            return Err(Error::InvalidArgument(
                "max_inputs".to_owned(),
                "need at least 2 inputs to be able to merge".to_owned(),
            ));
        }

        // All inputs must be of the correct token id.
        if inputs.iter().any(|utxo| utxo.token_id != *token_id) {
            return Err(Error::InvalidArgument(
                "inputs".to_string(),
                format!("All inputs must be of token_id {token_id}"),
            ));
        }

        let mut spendable_inputs: Vec<&UnspentTxOut> = inputs
            .iter()
            .filter(|utxo| num_blocks_in_ledger >= utxo.attempted_spend_tombstone)
            .collect();

        // No point in merging if we are able to spend all inputs at once.
        if spendable_inputs.len() < max_inputs {
            return Err(Error::OptimizationNotBeneficial(
                "Not enough spendable UTXOs to require merging".to_owned(),
            ));
        }

        spendable_inputs.sort_by_key(|utxo| utxo.value);

        let biggest_utxo = spendable_inputs.pop().unwrap();
        loop {
            // If there are no spendable inputs, we've tried merging all of them and still
            // ended up losing it all to fees.
            if spendable_inputs.is_empty() {
                return Err(Error::OptimizationNotBeneficial(
                    "Merging UTXOs would result in a loss".to_owned(),
                ));
            }

            let mut total = 0;
            let mut selected_utxos = Vec::new();
            for utxo in spendable_inputs.iter().take(max_inputs - 1).cloned() {
                selected_utxos.push(utxo);
                total += utxo.value;
            }

            // See if the total amount we are trying to merge into our biggest UTXO is
            // bigger than the fee. If it's smaller, the merge would just lose
            // us money.
            if total > fee {
                // Grab the UTXO we are merging into and stop iterating.
                selected_utxos.push(biggest_utxo);

                // Sanity - the amount we're moving sans the fee needs to increase the value of
                // our biggest UTXO.
                let total_value: u64 = selected_utxos.iter().map(|utxo| utxo.value).sum();
                assert!(total_value - fee > biggest_utxo.value);

                // Return our selected utxos and fee.
                return Ok(selected_utxos.into_iter().cloned().collect());
            }

            // Merging the currently selected set of UTXOs would lose us money. Try again
            // without the smallest UTXO.
            spendable_inputs.remove(0);
        }
    }

    /// Get membership proofs for a list of transaction outputs.
    pub fn get_membership_proofs(
        &self,
        outputs: &[TxOut],
    ) -> Result<Vec<TxOutMembershipProof>, Error> {
        let indexes = outputs
            .iter()
            .map(|tx_out| self.ledger_db.get_tx_out_index_by_hash(&tx_out.hash()))
            .collect::<Result<Vec<u64>, LedgerError>>()?;
        Ok(self.ledger_db.get_tx_out_proof_of_memberships(&indexes)?)
    }

    /// Get `num_rings` rings of mixins.
    pub fn get_rings(
        &self,
        ring_size: usize,
        num_rings: usize,
        excluded_tx_out_indices: &[u64],
    ) -> Result<Vec<Vec<(TxOut, TxOutMembershipProof)>>, Error> {
        let num_requested = ring_size * num_rings;
        let num_txos = self.ledger_db.num_txos()?;

        // Check that the ledger contains enough tx outs.
        if excluded_tx_out_indices.len() as u64 > num_txos {
            return Err(Error::InvalidArgument(
                "excluded_tx_out_indices".to_string(),
                "exceeds amount of tx outs in ledger".to_string(),
            ));
        }

        if num_requested > (num_txos as usize - excluded_tx_out_indices.len()) {
            return Err(Error::InsufficientTxOuts);
        }

        // Randomly sample `num_requested` indices of TxOuts to use as mixins.
        let mixin_indices: Vec<u64> = {
            let mut rng = rand::thread_rng();
            let mut samples: HashSet<u64> = HashSet::default();
            while samples.len() < num_requested {
                let index = rng.gen_range(0..num_txos);
                if excluded_tx_out_indices.contains(&index) {
                    continue;
                }
                samples.insert(index);
            }
            samples.into_iter().collect()
        };

        let mixins_result: Result<Vec<TxOut>, _> = mixin_indices
            .iter()
            .map(|&index| self.ledger_db.get_tx_out_by_index(index))
            .collect();
        let mixins: Vec<TxOut> = mixins_result?;

        let membership_proofs = self
            .ledger_db
            .get_tx_out_proof_of_memberships(&mixin_indices)?;

        let mixins_with_proofs: Vec<(TxOut, TxOutMembershipProof)> = mixins
            .into_iter()
            .zip(membership_proofs.into_iter())
            .collect();

        // Group mixins and proofs into individual rings.
        let result: Vec<Vec<(_, _)>> = mixins_with_proofs
            .chunks(ring_size)
            .map(|chunk| chunk.to_vec())
            .collect();

        Ok(result)
    }

    /// Create a TxProposal.
    ///
    /// # Arguments
    /// * `inputs` - UTXOs to spend, with membership proofs.
    /// * `rings` - A set of mixins for each input, with membership proofs.
    /// * `block_version` - The block version to target for this transaction
    /// * `token_id` - The token id to transact in
    /// * `fee` - Transaction fee, in picoMOB.
    /// * `from_account_key` - Owns the inputs. Also the recipient of any
    ///   change.
    /// * `change_subaddress` - Subaddress for change recipient.
    /// * `destinations` - Outputs of the transaction.
    /// * `tombstone_block` - Tombstone block of the transaciton.
    /// * `fog_pubkey_resolver` - Provides Fog key report, when Fog is enabled.
    /// * `opt_memo_builder` - Optional memo builder to use instead of the
    ///   default one (EmptyMemoBuilder).
    /// * `fee_map` - The current minimum fee map consensus is configured with.
    /// * `rng` - randomness
    /// * `logger` - Logger
    #[allow(clippy::too_many_arguments)]
    fn build_tx_proposal(
        inputs: &[(UnspentTxOut, TxOutMembershipProof)],
        rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
        block_version: BlockVersion,
        token_id: TokenId,
        fee: u64,
        from_account_key: &AccountKey,
        change_subaddress: u64,
        destinations: &[Outlay],
        tombstone_block: BlockIndex,
        fog_resolver_factory: &Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync>,
        opt_memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
        fee_map: FeeMap,
        rng: &mut (impl RngCore + CryptoRng),
        logger: &Logger,
    ) -> Result<TxProposal, Error> {
        // Check that number of rings matches number of inputs.
        if rings.len() != inputs.len() {
            let err = format!(
                "rings/inputs mismatch: {:?} rings but {:?} inputs.",
                rings.len(),
                inputs.len()
            );
            log::error!(logger, "{}", err);
            return Err(Error::TxBuild(err));
        }

        // Check that we have at least one destination.
        if destinations.is_empty() {
            return Err(Error::TxBuild("Must have at least one destination".into()));
        }

        // Collect all required FogUris from public addresses, then pass to resolver
        // factory
        let fog_resolver = {
            let change_address = from_account_key.subaddress(change_subaddress);
            let fog_uris = core::slice::from_ref(&change_address)
                .iter()
                .chain(destinations.iter().map(|x| &x.receiver))
                .filter_map(|x| extract_fog_uri(x).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            fog_resolver_factory(&fog_uris).map_err(Error::Fog)?
        };

        // Create tx_builder.
        // TODO (GH #1522): Use RTH memo builder, optionally?
        let memo_builder: Box<dyn MemoBuilder + Send + Sync> = opt_memo_builder
            .unwrap_or_else(|| Box::<mc_transaction_builder::EmptyMemoBuilder>::default());

        let fee_amount = Amount::new(fee, token_id);
        let mut tx_builder =
            TransactionBuilder::new_with_box(block_version, fee_amount, fog_resolver, memo_builder)
                .map_err(|err| {
                    Error::TxBuild(format!("Error creating transaction builder: {err}"))
                })?;
        tx_builder.set_fee_map(fee_map);

        // Unzip each vec of tuples into a tuple of vecs.
        let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
            .into_iter()
            .map(|tuples| tuples.into_iter().unzip())
            .collect();

        // Add inputs to the tx.
        for (utxo, proof) in inputs {
            let (mut ring, mut membership_proofs) = rings_and_proofs
                .pop()
                .ok_or_else(|| Error::TxBuild("rings_and_proofs was empty".to_string()))?;
            assert_eq!(
                ring.len(),
                membership_proofs.len(),
                "Each ring element must have a corresponding membership proof."
            );

            // Add the input to the ring.
            let position_opt = ring.iter().position(|tx_out| *tx_out == utxo.tx_out);
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
                        ring.push(utxo.tx_out.clone());
                        membership_proofs.push(proof.clone());
                    } else {
                        // Replace the first element of the ring.
                        ring[0] = utxo.tx_out.clone();
                        membership_proofs[0] = proof.clone();
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

            let public_key = RistrettoPublic::try_from(&utxo.tx_out.public_key).unwrap();
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                from_account_key.view_private_key(),
                &from_account_key.subaddress_spend_private(utxo.subaddress_index),
            );

            let key_image = KeyImage::from(&onetime_private_key);
            log::debug!(
                logger,
                "Adding input: ring {:?}, utxo index {:?}, key image {:?}, pubkey {:?}",
                ring,
                real_key_index,
                key_image,
                public_key
            );

            tx_builder.add_input(
                InputCredentials::new(
                    ring,
                    membership_proofs,
                    real_key_index,
                    onetime_private_key,
                    *from_account_key.view_private_key(),
                )
                .map_err(|_| Error::TxBuild("failed creating InputCredentials".into()))?,
            );
        }

        // Add outputs to our destinations.
        let mut total_value = 0;
        let mut tx_out_to_outlay_index = HashMap::default();
        let mut outlay_confirmation_numbers = Vec::default();
        for (i, outlay) in destinations.iter().enumerate() {
            // TODO (GH #1867): If you want to support mixed transactions, use
            // outlay-specific token id here
            let amount = Amount {
                value: outlay.value,
                token_id,
            };
            let TxOutContext {
                tx_out,
                confirmation,
                ..
            } = tx_builder
                .add_output(amount, &outlay.receiver, rng)
                .map_err(|err| Error::TxBuild(format!("failed adding output: {err}")))?;

            tx_out_to_outlay_index.insert(tx_out, i);
            outlay_confirmation_numbers.push(confirmation);

            total_value += outlay.value;
        }

        // Figure out if we have change.
        let input_value = inputs
            .iter()
            .fold(0, |acc, (utxo, _proof)| acc + utxo.value);
        if total_value > input_value {
            return Err(Error::InsufficientFunds);
        }
        let change = input_value - total_value - tx_builder.get_fee();

        // If we do have nonzero change, add an output for that as well.
        // TODO (GH #1522): Should the exchange write destination memos?
        // If so then we must always write a change output, even if the change is zero
        if change > 0 {
            // TODO: If you want to support mixed transactions, use outlay-specific token id
            // here
            let change_amount = Amount {
                value: change,
                token_id,
            };

            let change_dest = ReservedSubaddresses::from_subaddress_index(
                from_account_key,
                Some(change_subaddress),
                None,
            );

            tx_builder
                .add_change_output(change_amount, &change_dest, rng)
                .map_err(|err| Error::TxBuild(format!("failed adding output (change): {err}")))?;
        }

        // Set tombstone block.
        tx_builder.set_tombstone_block(tombstone_block);

        // Build tx.
        let tx = tx_builder
            .build(&NoKeysRingSigner {}, rng)
            .map_err(|err| Error::TxBuild(format!("build tx failed: {err}")))?;

        // Map each TxOut in the constructed transaction to its respective outlay.
        let outlay_index_to_tx_out_index = tx
            .prefix
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(tx_out_index, tx_out)| {
                tx_out_to_outlay_index
                    .get(tx_out)
                    .map(|outlay_index| (*outlay_index, tx_out_index))
            })
            .collect::<HashMap<_, _>>();

        // Sanity check: All of our outlays should have a unique index in the map.
        assert_eq!(outlay_index_to_tx_out_index.len(), destinations.len());
        let mut found_tx_out_indices = HashSet::default();
        for i in 0..destinations.len() {
            let tx_out_index = outlay_index_to_tx_out_index
                .get(&i)
                .expect("index not in map");
            if !found_tx_out_indices.insert(tx_out_index) {
                panic!("duplicate index {tx_out_index} found in map");
            }
        }

        // Return the TxProposal
        let selected_utxos = inputs
            .iter()
            .map(|(utxo, _membership_proof)| utxo.clone())
            .collect();

        Ok(TxProposal {
            utxos: selected_utxos,
            outlays: destinations.to_vec(),
            tx,
            outlay_index_to_tx_out_index,
            outlay_confirmation_numbers,
        })
    }
}

// Helper which extracts FogUri from PublicAddress or returns None, or returns
// an error
fn extract_fog_uri(addr: &PublicAddress) -> Result<Option<FogUri>, Error> {
    if let Some(string) = addr.fog_report_url() {
        Ok(Some(FogUri::from_str(string).map_err(|err| {
            Error::Fog(format!("Could not parse recipient Fog Url: {err}"))
        })?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_connection::{HardcodedCredentialsProvider, ThickClient};
    use mc_crypto_keys::RistrettoPrivate;
    use mc_fog_report_validation::MockFogPubkeyResolver;
    use mc_transaction_core::{constants::MILLIMOB_TO_PICOMOB, tokens::Mob, Amount, Token};
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_utxos(num_utxos: usize) -> Vec<UnspentTxOut> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let alice = AccountKey::random(&mut rng);
        let tx_secret_key_for_txo = RistrettoPrivate::from_random(&mut rng);

        let token_id = Mob::ID;

        let tx_out = TxOut::new(
            BlockVersion::MAX,
            Amount { value: 1, token_id },
            &alice.default_subaddress(),
            &tx_secret_key_for_txo,
            Default::default(),
        )
        .unwrap();

        // Construct a bunch of utxos.
        (0..num_utxos as u64)
            .map(|_| UnspentTxOut {
                tx_out: tx_out.clone(),
                subaddress_index: 0,
                key_image: Default::default(),
                value: 1,
                attempted_spend_height: 0,
                attempted_spend_tombstone: 0,
                token_id: *token_id,
            })
            .collect()
    }

    #[test]
    fn test_select_utxos_for_value_selects_smallest_inputs() {
        let mut utxos = generate_utxos(5);

        utxos[0].value = 100;
        utxos[1].value = 200;
        utxos[2].value = 300;
        utxos[3].value = 2000;
        utxos[4].value = 1000;

        // Sending 300 should select 100 + 200 when 2 inputs are allowed.
        let selected_utxos = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_value(Mob::ID, &utxos, 300, utxos.len())
        .unwrap();

        assert_eq!(selected_utxos, vec![utxos[0].clone(), utxos[1].clone()]);

        // Sending 301 should select 100 + 200 + 300 when 3 inputs are allowed.
        let selected_utxos = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_value(Mob::ID, &utxos, 301, utxos.len())
        .unwrap();

        assert_eq!(
            selected_utxos,
            vec![utxos[0].clone(), utxos[1].clone(), utxos[2].clone()]
        );

        // Sending 301 should select 200 + 300 when only 2  inputs are allowed.
        let selected_utxos = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_value(Mob::ID, &utxos, 301, 2)
        .unwrap();

        assert_eq!(selected_utxos, vec![utxos[1].clone(), utxos[2].clone()]);
    }

    #[test]
    fn test_select_utxos_for_value_errors_if_too_many_inputs_are_needed() {
        let utxos = generate_utxos(10);
        // While we have enough utxos to sum to 5, if the input limit is 4 we should
        // fail.
        match TransactionsManager::<ThickClient<HardcodedCredentialsProvider>, MockFogPubkeyResolver>::select_utxos_for_value(
            Mob::ID, &utxos, 5, 4,
        ) {
            Err(Error::InsufficientFundsFragmentedUtxos) => {
                // Expected.
            }
            _ => panic!("Did not get expected error"),
        };
    }

    #[test]
    fn test_select_utxos_for_value_errors_if_insufficient_funds() {
        let utxos = generate_utxos(10);
        // While we have enough utxos to sum to 5, if the input limit is 4 we should
        // fail.
        match TransactionsManager::<ThickClient<HardcodedCredentialsProvider>, MockFogPubkeyResolver>::select_utxos_for_value(
            Mob::ID, &utxos, 50, 100,
        ) {
            Err(Error::InsufficientFunds) => {
                // Expected.
            }
            _ => panic!("Did not get expected error"),
        };
    }

    #[test]
    fn test_select_utxos_for_optimization_selects_smallest_inputs() {
        // Optimizing with max_inputs=2 should select 100, 2000
        {
            let mut utxos = generate_utxos(6);

            utxos[0].value = 100 * MILLIMOB_TO_PICOMOB;
            utxos[1].value = 200 * MILLIMOB_TO_PICOMOB;
            utxos[2].value = 150 * MILLIMOB_TO_PICOMOB;
            utxos[3].value = 300 * MILLIMOB_TO_PICOMOB;
            utxos[4].value = 2000 * MILLIMOB_TO_PICOMOB;
            utxos[5].value = 1000 * MILLIMOB_TO_PICOMOB;

            let selected_utxos = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 2, Mob::ID, Mob::MINIMUM_FEE
            )
            .unwrap();

            assert_eq!(selected_utxos, vec![utxos[0].clone(), utxos[4].clone()]);
        }

        // Optimizing with max_inputs=3 should select 100, 150, 2000;
        {
            let mut utxos = generate_utxos(6);

            utxos[0].value = 100 * MILLIMOB_TO_PICOMOB;
            utxos[1].value = 200 * MILLIMOB_TO_PICOMOB;
            utxos[2].value = 150 * MILLIMOB_TO_PICOMOB;
            utxos[3].value = 300 * MILLIMOB_TO_PICOMOB;
            utxos[4].value = 2000 * MILLIMOB_TO_PICOMOB;
            utxos[5].value = 1000 * MILLIMOB_TO_PICOMOB;

            let selected_utxos = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 3, Mob::ID, Mob::MINIMUM_FEE
            )
            .unwrap();

            assert_eq!(
                selected_utxos,
                vec![utxos[0].clone(), utxos[2].clone(), utxos[4].clone()]
            );
        }
    }

    // Test behavior around the fee amount (off by one, exact fee, etc).
    #[test]
    fn test_select_utxos_for_optimization_behavior_around_fee() {
        // When the sum of available UTXOs is lower than the fee, no merging will take
        // place.
        {
            let mut utxos = generate_utxos(6);

            utxos[0].value = Mob::MINIMUM_FEE / 10;
            utxos[1].value = Mob::MINIMUM_FEE / 10;
            utxos[2].value = Mob::MINIMUM_FEE / 10;
            utxos[3].value = Mob::MINIMUM_FEE / 10;
            utxos[4].value = 200 * Mob::MINIMUM_FEE;
            utxos[5].value = Mob::MINIMUM_FEE / 10;

            assert!(
                utxos[0].value + utxos[1].value + utxos[2].value + utxos[3].value + utxos[5].value
                    < Mob::MINIMUM_FEE
            );

            let result = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 100, Mob::ID, Mob::MINIMUM_FEE
            );
            assert!(result.is_err());
        }

        // When the sum of available UTXOs is exactly equal the fee amount, no merging
        // will ltake place.
        {
            let mut utxos = generate_utxos(2);

            utxos[0].value = Mob::MINIMUM_FEE;
            utxos[1].value = 2000 * MILLIMOB_TO_PICOMOB;

            let result = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 100, Mob::ID, Mob::MINIMUM_FEE
            );
            assert!(result.is_err());
        }

        // When the sum if available UTXOs is higher than the fee, merging is possible.
        {
            let mut utxos = generate_utxos(4);

            utxos[0].value = Mob::MINIMUM_FEE;
            utxos[1].value = 208 * Mob::MINIMUM_FEE;
            utxos[2].value = Mob::MINIMUM_FEE / 10;
            utxos[3].value = Mob::MINIMUM_FEE / 5;

            let selected_utxos = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 3, Mob::ID, Mob::MINIMUM_FEE
            )
            .unwrap();
            // Since we're limited to 3 inputs, the lowest input (of value 1) is going to
            // get excluded.
            assert_eq!(
                selected_utxos,
                vec![utxos[3].clone(), utxos[0].clone(), utxos[1].clone()]
            );
        }
    }

    // Attempting to select from a set of less than 2 UTXOs should fail
    #[test]
    fn test_select_utxos_for_optimizations_errors_on_less_than_2_utxos() {
        let mut utxos = generate_utxos(2);

        utxos[0].value = 2000 * MILLIMOB_TO_PICOMOB;
        utxos[1].value = 2000 * MILLIMOB_TO_PICOMOB;

        let result = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_optimization(
            1000, &[], 100, Mob::ID, Mob::MINIMUM_FEE
        );
        assert!(result.is_err());

        let result = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_optimization(
            1000, &utxos[0..1], 100, Mob::ID, Mob::MINIMUM_FEE
        );
        assert!(result.is_err());

        // A set of 2 utxos succeeds when max inputs is 2, but fails when it is 3 (since
        // there's no point to merge 2 when we can directly spend 3)
        let result = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_optimization(
            1000, &utxos[0..2], 2, Mob::ID, Mob::MINIMUM_FEE
        );
        assert!(result.is_ok());

        let result = TransactionsManager::<
            ThickClient<HardcodedCredentialsProvider>,
            MockFogPubkeyResolver,
        >::select_utxos_for_optimization(
            1000, &utxos[0..2], 3, Mob::ID, Mob::MINIMUM_FEE
        );
        assert!(result.is_err());
    }
}
