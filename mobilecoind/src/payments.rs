// Copyright (c) 2018-2024 The MobileCoin Foundation

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
use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
use mc_crypto_ring_signature_signer::NoKeysRingSigner;
use mc_fog_report_validation::FogPubkeyResolver;
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_rand::{CryptoRng, RngCore};
use mc_transaction_builder::{
    InputCredentials, MemoBuilder, ReservedSubaddresses, SignedContingentInputBuilder,
    TransactionBuilder, TxOutContext,
};
use mc_transaction_core::{
    constants::{MAX_INPUTS, RING_SIZE},
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, FeeMap, TokenId,
};
use mc_transaction_extra::{
    SignedContingentInput, SignedContingentInputAmounts, TxOutConfirmationNumber,
};
use mc_util_uri::FogUri;
use rand::Rng;
use std::{
    cmp::{max, Reverse},
    collections::BTreeMap,
    str::FromStr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

/// Default number of blocks used for calculating transaction tombstone block
/// number.
// TODO support for making this configurable
pub const DEFAULT_NEW_TX_BLOCK_ATTEMPTS: u64 = 50;

/// Default ring size
pub const DEFAULT_RING_SIZE: usize = RING_SIZE;

/// An outlay - the API representation of a desired transaction output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Outlay {
    /// Value being sent.
    pub value: u64,

    /// Destination.
    pub receiver: PublicAddress,

    /// Optional tx private key to use.
    pub tx_private_key: Option<RistrettoPrivate>,
}

/// An outlay, with token id information.
/// This is the V2 API representation of a desired transaction output, which
/// works with mixed transactions also.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutlayV2 {
    /// Amount being sent.
    pub amount: Amount,

    /// Destination.
    pub receiver: PublicAddress,

    /// Optional tx private key to use.
    pub tx_private_key: Option<RistrettoPrivate>,
}

/// A single pending transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxProposal {
    /// UTXOs used as inputs for this transaction.
    pub utxos: Vec<UnspentTxOut>,

    /// Destinations the transaction is being sent to.
    pub outlays: Vec<OutlayV2>,

    /// The actual transaction.
    pub tx: Tx,

    /// A map of outlay index -> TxOut index in the Tx object.
    /// This is needed to map recipients to their respective TxOuts.
    pub outlay_index_to_tx_out_index: HashMap<usize, usize>,

    /// A list of the confirmation numbers, in the same order
    /// as the outlays.
    pub outlay_confirmation_numbers: Vec<TxOutConfirmationNumber>,

    /// A list of scis that were incorporated into the Tx object
    pub scis: Vec<SciForTx>,
}

impl TxProposal {
    pub fn fee(&self) -> u64 {
        self.tx.prefix.fee
    }
}

/// A SignedContingentInput which the client wants to add to a new Tx, with
/// data about what degree to fill it, if it is a partial fill SCI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SciForTx {
    /// The signed contingent input to add to the transaction
    pub sci: SignedContingentInput,
    /// The amount to take from the maximum allowed volume of this SCI.
    /// The remainder is returned to the originator as change.
    /// For partial fill SCIs, this
    /// must be nonzero. For non-partial fill SCIs, this must be zero.
    pub partial_fill_value: u64,
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

    // Gets the network block version and fee information.
    //
    // * The block version is the max of the local ledger block version and the
    //   network-reported block version.
    // * If opt_fee is nonzero, then that fee value is returned. Otherwise, the
    //   minimum fee for this token id reported by the network is returned.
    //
    // If the network does not report a minimum fee for this token id, and the user
    // does not specify a nonzero fee, then we return an error.
    fn get_network_fee_and_block_version(
        &self,
        token_id: TokenId,
        opt_fee: u64,
        last_block_info: &BlockInfo,
    ) -> Result<(u64, u32), Error> {
        // Figure out the block_version, taking max of local ledger and network
        let block_version = max(
            self.ledger_db.get_latest_block()?.version,
            last_block_info.network_block_version,
        );

        // Figure out the fee using either user-specified fee, or the network-reported
        // fee.
        Ok(if opt_fee != 0 {
            (opt_fee, block_version)
        } else {
            let fee = last_block_info
                .minimum_fee_or_none(&token_id)
                .ok_or_else(|| Error::TxBuild("Token cannot be used to pay fees".into()))?;
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

    /// Create a TxProposal, using only one token id for the whole transaction.
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
    /// * `opt_fee` - Transaction fee value in smallest representable units. If
    ///   zero, use network-reported minimum fee.
    /// * `opt_tombstone` - Tombstone block. If zero, sets to default.
    /// * `memo_builder` - Memo builder to use.
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
        memo_builder: Box<dyn MemoBuilder + 'static + Send + Sync>,
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

        // Convert outlays into OutlayV2, using fee token id to set the token id.
        let outlays: Vec<OutlayV2> = outlays
            .iter()
            .map(|outlay_v1| OutlayV2 {
                receiver: outlay_v1.receiver.clone(),
                amount: Amount::new(outlay_v1.value, token_id),
                tx_private_key: outlay_v1.tx_private_key,
            })
            .collect();

        self.build_mixed_transaction(
            sender_monitor_id,
            token_id,
            change_subaddress,
            inputs,
            &[],
            &outlays,
            last_block_infos,
            opt_fee,
            opt_tombstone,
            Some(memo_builder),
        )
    }

    /// Create a TxProposal, possibly with mixed token ids.
    ///
    /// # Arguments
    /// * `sender_monitor_id` - Indicates the the account key needed to spend
    ///   the txo's.
    /// * `fee_token_id` - The token id to transact in.
    /// * `change_subaddress` - Recipient of any change.
    /// * `inputs` - UTXOs that will be spent by the transaction.
    /// * `scis` - SCIs to incorporate into the transaction
    /// * `outlays` - Output amounts and recipients.
    /// * `last_block_infos` - Last block info responses from the network, for
    ///   determining fees. This should normally come from polling_network_state
    /// * `opt_fee` - Transaction fee in smallest representable units. If zero,
    ///   use network-reported minimum fee.
    /// * `opt_tombstone` - Tombstone block. If zero, sets to default.
    /// * `opt_memo_builder` - Optional memo builder to use instead of the
    ///   default one (EmptyMemoBuilder).
    pub fn build_mixed_transaction(
        &self,
        sender_monitor_id: &MonitorId,
        fee_token_id: TokenId,
        change_subaddress: u64,
        inputs: &[UnspentTxOut],
        scis: &[SciForTx],
        outlays: &[OutlayV2],
        last_block_infos: &[BlockInfo],
        opt_fee: u64,
        opt_tombstone: u64,
        opt_memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(o!("sender_monitor_id" => sender_monitor_id.to_string(), "outlays" => format!("{outlays:?}")));
        log::trace!(logger, "Building pending transaction...");

        // Must have at least one output
        if outlays.is_empty() && scis.is_empty() {
            return Err(Error::TxBuild("Must have at least one destination".into()));
        }

        // Get sender monitor data.
        let sender_monitor_data = self.mobilecoind_db.get_monitor_data(sender_monitor_id)?;

        // Figure out the block version, fee and minimum fee map.
        let (fee, fee_map, block_version) =
            self.get_fee_info_and_block_version(last_block_infos, fee_token_id, opt_fee)?;

        // Compute what value of inputs we need to supply to satisfy the outputs and
        // balance the transaction.
        let mut balance_sheet = BTreeMap::<TokenId, i128>::default();
        *balance_sheet.entry(fee_token_id).or_default() += fee as i128;

        for outlay in outlays {
            *balance_sheet.entry(outlay.amount.token_id).or_default() +=
                outlay.amount.value as i128;
        }

        let mut scis_and_amounts = Vec::default();
        for sci_for_tx in scis {
            let sci_amounts = sci_for_tx.sci.validate()?;
            sci_amounts.add_to_balance_sheet(sci_for_tx.partial_fill_value, &mut balance_sheet)?;

            // While we are here, also attach membership proofs to the sci
            // It's assumed that SCI's are usually passed around without membership proofs,
            // and these are only added when we actually want to build a Tx.
            let mut sci_for_tx = sci_for_tx.clone();
            let proofs = self.get_membership_proofs(&sci_for_tx.sci.tx_in.ring)?;
            sci_for_tx.sci.tx_in.proofs = proofs;
            scis_and_amounts.push((sci_for_tx, sci_amounts));
        }

        // Select the UTXOs to be used for this transaction.
        let mut all_selected_utxos = vec![];
        for (token_id, val) in balance_sheet.iter() {
            if *val > 0 {
                let remaining_input_slots =
                    MAX_INPUTS as usize - all_selected_utxos.len() - scis.len();
                if remaining_input_slots == 0 {
                    return Err(Error::TxBuild(
                        "Ran out of input slots during input selection".to_string(),
                    ));
                }
                let selected_utxos = Self::select_utxos_for_value(
                    *token_id,
                    inputs,
                    *val as u64,
                    remaining_input_slots,
                )?;
                all_selected_utxos.extend(selected_utxos);
            }
        }
        log::trace!(
            logger,
            "Selected {} utxos ({:?})",
            all_selected_utxos.len(),
            all_selected_utxos,
        );

        // The selected_utxos with corresponding proofs of membership.
        let selected_utxos_with_proofs: Vec<(UnspentTxOut, TxOutMembershipProof)> = {
            let outputs: Vec<TxOut> = all_selected_utxos
                .iter()
                .map(|utxo| utxo.tx_out.clone())
                .collect();
            let proofs = self.get_membership_proofs(&outputs)?;

            all_selected_utxos.into_iter().zip(proofs).collect()
        };
        log::trace!(logger, "Got membership proofs");

        // A ring of mixins for each UTXO.
        let rings = {
            let mut excluded_tx_out_indices: Vec<u64> = selected_utxos_with_proofs
                .iter()
                .map(|(_, proof)| proof.index)
                .collect();

            for sci_for_tx in scis {
                excluded_tx_out_indices.extend(sci_for_tx.sci.tx_out_global_indices.clone());
            }

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
            &scis_and_amounts,
            block_version,
            fee_token_id,
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

    /// Create and return an SCI that offers to trade one of our inputs for a
    /// given amount of some currency. This SCI is in the form accepted by
    /// the deqs.
    ///
    /// # Arguments
    /// * `sender_monitor_id` - Indicates the account key needed to spend the
    ///   txo's.
    /// * `change_subaddress` - Recipient of any change.
    /// * `utxo` - UTXO that will be offered for swap
    /// * `counter_amount` - The amount that we are asking from the counterparty
    /// * `is_partial_fill` - Whether we allow partial fills of the quote, if
    ///   false then it is all or nothing.
    /// * `min_fill_value` - When it is a partial fill quote, the minimum amount
    ///   the counterparty must supply to match against the quote.
    /// * `last_block_infos` - Last block info responses from the network, for
    ///   determining block version. This should come from polling_network_state
    /// * `opt_tombstone` - Tombstone block. If zero, the swap offer doesn't
    ///   expire.
    /// * `opt_memo_builder` - Optional memo builder to use instead of the
    ///   default one (EmptyMemoBuilder).
    pub fn build_swap_proposal(
        &self,
        sender_monitor_id: &MonitorId,
        change_subaddress_index: u64,
        utxo: &UnspentTxOut,
        counter_amount: Amount,
        is_partial_fill: bool,
        min_fill_value: u64,
        last_block_infos: &[BlockInfo],
        opt_tombstone: u64,
        opt_memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
    ) -> Result<SignedContingentInput, Error> {
        let logger = self.logger.new(o!("sender_monitor_id" => sender_monitor_id.to_string(), "counter_amount" => format!("{counter_amount:?}")));
        log::trace!(logger, "Building swap proposal...");

        // Get sender monitor data.
        let sender_monitor_data = self.mobilecoind_db.get_monitor_data(sender_monitor_id)?;

        // Get the subaddress.
        let change_subaddress = sender_monitor_data
            .account_key
            .subaddress(change_subaddress_index);

        // Figure out the block version, fee and minimum fee map.
        let (_fee, _fee_map, block_version) =
            self.get_fee_info_and_block_version(last_block_infos, 0.into(), 0)?;

        // Get global index of the utxo
        let global_index = self
            .ledger_db
            .get_tx_out_index_by_hash(&utxo.tx_out.hash())?;
        log::trace!(logger, "Got global index: {}", global_index);

        // Get a ring of mixins and their proofs
        let ring = self.get_rings(DEFAULT_RING_SIZE, 1, &[global_index])?;
        // Convert to a ring of mixins and their indices
        let ring: Vec<(TxOut, u64)> = ring[0]
            .clone()
            .into_iter()
            .map(|(tx_out, _proof)| {
                let index = self.ledger_db.get_tx_out_index_by_hash(&tx_out.hash())?;
                Ok((tx_out, index))
            })
            .collect::<Result<_, Error>>()?;
        log::trace!(logger, "Got ring");

        let mut required_outputs = Vec::default();
        let mut fractional_outputs = Vec::default();

        // Add the counterparty amount either as a required or fractional output
        if is_partial_fill {
            fractional_outputs.push((counter_amount, change_subaddress));
        } else {
            required_outputs.push((counter_amount, change_subaddress));
        }

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let sci = Self::build_sci(
            utxo,
            global_index,
            ring,
            block_version,
            &sender_monitor_data.account_key,
            change_subaddress_index,
            None, // custom change_amount
            &required_outputs,
            &fractional_outputs,
            min_fill_value,
            opt_tombstone,
            &self.fog_resolver_factory,
            opt_memo_builder,
            &mut rng,
            &self.logger,
        )?;
        log::trace!(logger, "Sci constructed");

        Ok(sci)
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
                .get_utxos_for_subaddress(monitor_id, subaddress_index)?
                .into_iter()
                .filter(|utxo| utxo.token_id == *token_id)
                .collect::<Vec<_>>();
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

            selected_utxos.into_iter().zip(proofs).collect()
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
        let outlays = vec![OutlayV2 {
            receiver: monitor_data.account_key.subaddress(subaddress_index),
            amount: Amount::new(total_value - fee, token_id),
            tx_private_key: None,
        }];

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let tx_proposal = Self::build_tx_proposal(
            &selected_utxos_with_proofs,
            rings,
            &[],
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
            inputs.iter().cloned().zip(proofs).collect()
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
        let outlays = vec![OutlayV2 {
            receiver: receiver.clone(),
            amount: Amount::new(total_value - fee, token_id),
            tx_private_key: None,
        }];

        // Build and return the TxProposal object
        let mut rng = rand::thread_rng();
        let tx_proposal = Self::build_tx_proposal(
            &inputs_with_proofs,
            rings,
            &[],
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

        // The rationale for these retries is:
        // * Quite often, the attested connetion was closed and we need to retry once to
        //   re-attest, and this attestation is successful. So that takes 50 ms.
        // * After that, we back off to 500 ms, because there are rate limits of about
        //   100 / min in place in production.
        let retry_iterator = [50, 500, 500, 750, 1000]
            .iter()
            .cloned()
            .map(Duration::from_millis);

        // Try and submit.
        let block_height = self
            .peer_manager
            .conn(responder_id)
            .ok_or(Error::NodeNotFound)?
            .propose_tx(&tx_proposal.tx, retry_iterator)
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
    ///    unknown state.
    /// 2) Sort remaining UTXOs in ascending order (by their value).
    /// 3) Grab the largest available UTXO, and MAX_INPUTS-1 smallest available
    ///    UTXOs. 4) If the sum of the smallest available UTXOs > fee, we would
    ///    be able to increase our largest UTXO and we're done. If not, try
    ///    again without the smallest UTXO.
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

        let mixins_with_proofs: Vec<(TxOut, TxOutMembershipProof)> =
            mixins.into_iter().zip(membership_proofs).collect();

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
    /// * `scis` - A set of scis to add to the Tx. Assumes SCI's already
    ///   validated and had proofs added. The Sci Amounts from validation also
    ///   need to be included.
    /// * `block_version` - The block version to target for this transaction
    /// * `fee_token_id` - The token id of the fee
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
        scis: &[(SciForTx, SignedContingentInputAmounts)],
        block_version: BlockVersion,
        fee_token_id: TokenId,
        fee: u64,
        from_account_key: &AccountKey,
        change_subaddress: u64,
        destinations: &[OutlayV2],
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

        // Check that we have at least one destination, or SCIs are involved
        if destinations.is_empty() && scis.is_empty() {
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

        // This balance sheet will be used to keep track of the balance across
        // the whole Tx, and then determine what change outputs to write.
        // Outlays are positive and inputs are negative.
        let mut balance_sheet = BTreeMap::<TokenId, i128>::default();
        *balance_sheet.entry(fee_token_id).or_default() += fee as i128;

        let fee_amount = Amount::new(fee, fee_token_id);
        let mut tx_builder = TransactionBuilder::new(block_version, fee_amount, fog_resolver)
            .map_err(|err| Error::TxBuild(format!("Error creating transaction builder: {err}")))?;
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
                        // The ring is probably not empty, but ring[0] will panic if it is.
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

            let public_key = RistrettoPublic::try_from(&utxo.tx_out.public_key)?;
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
            *balance_sheet.entry(utxo.token_id.into()).or_default() -= utxo.value as i128;
        }

        for (sci_for_tx, sci_amounts) in scis {
            if sci_for_tx.partial_fill_value == 0 {
                tx_builder.add_presigned_input(sci_for_tx.sci.clone())?;
            } else {
                // The tx_builder expects to be given the partial fill change value,
                // when the sci is a partial fill. However our API is that the user
                // passes the amount the user wants to claim out of the partial
                // fill change value. So we have to subtract.
                let partial_fill_change = sci_amounts
                    .partial_fill_change
                    .as_ref()
                    .ok_or_else(|| Error::TxBuild("sci is missing partial fill change".into()))?;

                if sci_for_tx.partial_fill_value > partial_fill_change.value {
                    return Err(Error::TxBuild(format!(
                        "sci partial fill amount is invalid: {} > {}",
                        sci_for_tx.partial_fill_value, partial_fill_change.value,
                    )));
                }
                let real_change_amount = Amount::new(
                    partial_fill_change.value - sci_for_tx.partial_fill_value,
                    partial_fill_change.token_id,
                );
                tx_builder
                    .add_presigned_partial_fill_input(sci_for_tx.sci.clone(), real_change_amount)?;
            }
            sci_amounts.add_to_balance_sheet(sci_for_tx.partial_fill_value, &mut balance_sheet)?;
        }

        // Add outputs to our destinations.
        let mut tx_out_public_key_to_outlay_index = HashMap::default();
        let mut outlay_confirmation_numbers = Vec::default();
        for (i, outlay) in destinations.iter().enumerate() {
            let TxOutContext {
                tx_out_public_key,
                confirmation,
                ..
            } = tx_builder
                .add_output_with_tx_private_key(
                    outlay.amount,
                    &outlay.receiver,
                    outlay.tx_private_key,
                    rng,
                )
                .map_err(|err| Error::TxBuild(format!("failed adding output: {err}")))?;

            tx_out_public_key_to_outlay_index.insert(tx_out_public_key, i);
            outlay_confirmation_numbers.push(confirmation);

            *balance_sheet.entry(outlay.amount.token_id).or_default() +=
                outlay.amount.value as i128;
        }

        // Figure out if we have change. Change occurs when the total value of the
        // inputs exceeds the value of the outlays, so we have a negative entry
        // in the balance sheet.
        let change_dest = ReservedSubaddresses::from_subaddress_index(
            from_account_key,
            Some(change_subaddress),
            None,
        );

        for (token_id, val) in balance_sheet.iter() {
            if *val > 0 {
                log::error!(
                    logger,
                    "After input selection we still had an insufficient amount of {}: {}",
                    token_id,
                    val
                );
                return Err(Error::InsufficientFunds);
            }
            // When val is negative, that means we have change, because the inputs were
            // larger than was strictly needed to fulfill the outlays.
            // Note: RTH normally requires that we write change even if it's zero, but we
            // haven't done that here yet, and we're always writing empty memos.
            // Note: RTH doesn't tolerate having multiple change outputs right now IIRC,
            // so we would have to extend the scope of RTH to work with complex mixed
            // transactions that have multiple change outputs, if we want that
            // to work.
            if *val < 0 {
                let change_val = u64::try_from(-*val).map_err(|_| {
                    Error::TxBuild(format!("change value overflowed a u64: {}", -*val))
                })?;
                let change_amount = Amount::new(change_val, *token_id);

                tx_builder
                    .add_change_output(change_amount, &change_dest, rng)
                    .map_err(|err| {
                        Error::TxBuild(format!("failed adding output (change): {err}"))
                    })?;
            }
        }

        // Set tombstone block.
        tx_builder.set_tombstone_block(tombstone_block);

        // Build tx.
        let tx = tx_builder
            .build(&NoKeysRingSigner {}, memo_builder, rng)
            .map_err(|err| Error::TxBuild(format!("build tx failed: {err}")))?;

        // Map each TxOut in the constructed transaction to its respective outlay.
        let outlay_index_to_tx_out_index = tx
            .prefix
            .outputs
            .iter()
            .enumerate()
            .filter_map(|(tx_out_index, tx_out)| {
                tx_out_public_key_to_outlay_index
                    .get(&tx_out.public_key)
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
            scis: scis
                .iter()
                .cloned()
                .map(|(mut sci_for_tx, _sci_amount)| {
                    // clear out proofs here since they were not part of the request
                    sci_for_tx.sci.tx_in.proofs = Vec::default();
                    sci_for_tx
                })
                .collect(),
        })
    }

    /// Create a SignedContingentInput.
    ///
    /// # Arguments
    /// * `utxo` - UTXO to spend
    /// * `global_index` - The global index of the input
    /// * `ring` - A set of mixins for the input, with their global indices.
    /// * `block_version` - The block version to target for this transaction
    /// * `from_account_key` - Owns the inputs. Also the recipient of any
    ///   change.
    /// * `change_subaddress_index` - Subaddress for change recipient.
    /// * `change_amount` - The amount we will return to ourself as change. Must
    ///   match token id of input, and be between 0 and input. If there are
    ///   fractional outputs, this will be a fractional change output, otherwise
    ///   a required change output.
    /// * `required_outputs` - Required outputs of the sci.
    /// * `fractional_outputs` - Fractional outputs of the sci.
    /// * `min_fill_value` - The minimum amount that the counterparty must fill
    ///   the partial fill order to. Ignored if zero.
    /// * `tombstone_block` - Tombstone block of the sci. If 0, it is omitted,
    ///   and the sci does not expire unless fog forces it to.
    /// * `fog_pubkey_resolver` - Provides Fog key report, when Fog is enabled.
    /// * `opt_memo_builder` - Optional memo builder to use instead of the
    ///   default one (EmptyMemoBuilder).
    /// * `rng` - randomness
    /// * `logger` - Logger
    #[allow(clippy::too_many_arguments)]
    fn build_sci(
        utxo: &UnspentTxOut,
        global_index: u64,
        ring: Vec<(TxOut, u64)>,
        block_version: BlockVersion,
        from_account_key: &AccountKey,
        change_subaddress_index: u64,
        change_amount: Option<Amount>,
        required_outputs: &[(Amount, PublicAddress)],
        fractional_outputs: &[(Amount, PublicAddress)],
        min_fill_value: u64,
        tombstone_block: BlockIndex,
        fog_resolver_factory: &Arc<dyn Fn(&[FogUri]) -> Result<FPR, String> + Send + Sync>,
        opt_memo_builder: Option<Box<dyn MemoBuilder + 'static + Send + Sync>>,
        rng: &mut (impl RngCore + CryptoRng),
        _logger: &Logger,
    ) -> Result<SignedContingentInput, Error> {
        // Check that we have at least one destination.
        if required_outputs.is_empty() && fractional_outputs.is_empty() {
            return Err(Error::TxBuild("Must have at least one destination".into()));
        }

        // Collect all required FogUris from public addresses, then pass to resolver
        // factory
        let fog_resolver = {
            let change_address = from_account_key.subaddress(change_subaddress_index);
            let fog_uris = core::slice::from_ref(&change_address)
                .iter()
                .chain(required_outputs.iter().map(|x| &x.1))
                .chain(fractional_outputs.iter().map(|x| &x.1))
                .filter_map(|x| extract_fog_uri(x).transpose())
                .collect::<Result<Vec<_>, _>>()?;
            fog_resolver_factory(&fog_uris).map_err(Error::Fog)?
        };

        let (mut ring, mut global_indices): (Vec<TxOut>, Vec<u64>) = ring.into_iter().unzip();

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
                    // The ring is probably not empty, but ring[0] will panic if it is.
                    // Append the input and its proof of membership.
                    ring.push(utxo.tx_out.clone());
                    global_indices.push(global_index);
                } else {
                    // Replace the first element of the ring.
                    ring[0] = utxo.tx_out.clone();
                    global_indices[0] = global_index;
                }
                // The real input is always the first element. This is safe because
                // TransactionBuilder sorts each ring.
                0
            }
        };

        let membership_proofs: Vec<TxOutMembershipProof> = global_indices
            .into_iter()
            .map(|index| TxOutMembershipProof {
                index,
                ..Default::default()
            })
            .collect();

        // Create input credentials
        let input_credentials = {
            assert_eq!(
                ring.len(),
                membership_proofs.len(),
                "Each ring element must have a corresponding membership proof."
            );

            let public_key = RistrettoPublic::try_from(&utxo.tx_out.public_key)?;
            let onetime_private_key = recover_onetime_private_key(
                &public_key,
                from_account_key.view_private_key(),
                &from_account_key.subaddress_spend_private(utxo.subaddress_index),
            );

            InputCredentials::new(
                ring,
                membership_proofs,
                real_key_index,
                onetime_private_key,
                *from_account_key.view_private_key(),
            )
            .map_err(|_| Error::TxBuild("failed creating InputCredentials".into()))?
        };

        // Create sci_builder.
        // TODO (GH #1522): Use RTH memo builder, optionally?
        // Note: Clippy thinks the closure is redundant, but it doesn't build without
        // it.
        #[allow(clippy::redundant_closure)]
        let memo_builder: Box<dyn MemoBuilder + Send + Sync> = opt_memo_builder
            .unwrap_or_else(|| Box::<mc_transaction_builder::EmptyMemoBuilder>::default());

        let mut sci_builder = SignedContingentInputBuilder::new_with_box(
            block_version,
            input_credentials,
            fog_resolver,
            memo_builder,
        )
        .map_err(|err| {
            Error::TxBuild(format!(
                "Error creating signed contingent input builder: {err}"
            ))
        })?;

        // Add outputs to our destinations.
        for (amount, recipient) in required_outputs.iter() {
            sci_builder
                .add_required_output(*amount, recipient, rng)
                .map_err(|err| Error::TxBuild(format!("failed adding required output: {err}")))?;
        }
        for (amount, recipient) in fractional_outputs.iter() {
            sci_builder
                .add_partial_fill_output(*amount, recipient, rng)
                .map_err(|err| Error::TxBuild(format!("failed adding fractional output: {err}")))?;
        }

        // Add an appropriate change output to the sci
        if let Some(change_amount) = change_amount.as_ref() {
            if change_amount.token_id != utxo.token_id {
                return Err(Error::TxBuild("Incorrect change Token Id".to_string()));
            }
            if change_amount.value > utxo.value {
                return Err(Error::InsufficientFunds);
            }
        }

        let change_dest = ReservedSubaddresses::from_subaddress_index(
            from_account_key,
            Some(change_subaddress_index),
            None,
        );

        if fractional_outputs.is_empty() {
            // When we have an all-or-nothing swap and no change value is given,
            // we don't have to add a change output. (Maybe we should add a zero-value
            // change?) If one is specified, add it.
            if let Some(change_amount) = change_amount.as_ref() {
                sci_builder
                    .add_required_change_output(*change_amount, &change_dest, rng)
                    .map_err(|err| {
                        Error::TxBuild(format!("failed adding output (change): {err}"))
                    })?;
            }
        } else {
            // When we have a partial fill swap and no custom change value is given,
            // add a fractional change output equal in value to the input.
            let change_amount =
                change_amount.unwrap_or_else(|| Amount::new(utxo.value, utxo.token_id.into()));

            sci_builder
                .add_partial_fill_change_output(change_amount, &change_dest, rng)
                .map_err(|err| Error::TxBuild(format!("failed adding output (change): {err}")))?;

            sci_builder.set_min_partial_fill_value(min_fill_value);
        }

        // Set tombstone block.
        if tombstone_block != 0 {
            sci_builder.set_tombstone_block(tombstone_block);
        }

        // Build sci.
        let result = sci_builder
            .build(&NoKeysRingSigner {}, rng)
            .map_err(|err| Error::TxBuild(format!("build tx failed: {err}")))?;

        Ok(result)
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
    use mc_fog_report_validation::MockFogPubkeyResolver;
    use mc_transaction_core::{constants::MILLIMOB_TO_PICOMOB, tokens::Mob, Token};
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
                memo_payload: vec![],
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

    #[test]
    fn test_select_utxos_for_optimization_works_with_eusd() {
        // Optimizing with max_inputs=2 should select 100, 2000
        {
            let mut utxos = generate_utxos(6);
            let eusd = TokenId::from(1);

            utxos[0].value = 100 * MILLIMOB_TO_PICOMOB;
            utxos[1].value = 200 * MILLIMOB_TO_PICOMOB;
            utxos[2].value = 150 * MILLIMOB_TO_PICOMOB;
            utxos[3].value = 300 * MILLIMOB_TO_PICOMOB;
            utxos[4].value = 2000 * MILLIMOB_TO_PICOMOB;
            utxos[5].value = 1000 * MILLIMOB_TO_PICOMOB;
            utxos[0].token_id = *eusd;
            utxos[1].token_id = *eusd;
            utxos[2].token_id = *eusd;
            utxos[3].token_id = *eusd;
            utxos[4].token_id = *eusd;
            utxos[5].token_id = *eusd;

            let selected_utxos = TransactionsManager::<
                ThickClient<HardcodedCredentialsProvider>,
                MockFogPubkeyResolver,
            >::select_utxos_for_optimization(
                1000, &utxos, 2, eusd, Mob::MINIMUM_FEE
            )
            .unwrap();

            assert_eq!(selected_utxos, vec![utxos[0].clone(), utxos[4].clone()]);
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
