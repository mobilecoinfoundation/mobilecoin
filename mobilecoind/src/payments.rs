// Copyright (c) 2018-2020 MobileCoin Inc.

//! Construct and submit transactions to the validator network.

use crate::{database::Database, error::Error, monitor_store::MonitorId, utxo_store::UnspentTxOut};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_common::{
    logger::{log, o, Logger},
    HashMap, HashSet,
};
use mc_connection::{ConnectionManager, RetryableUserTxConnection, UserTxConnection};
use mc_crypto_keys::RistrettoPublic;
use mc_crypto_rand::{CryptoRng, RngCore};
use mc_ledger_db::{Error as LedgerError, Ledger, LedgerDB};
use mc_transaction_core::{
    constants::{MAX_INPUTS, MINIMUM_FEE, RING_SIZE},
    onetime_keys::recover_onetime_private_key,
    ring_signature::KeyImage,
    tx::{Tx, TxOut, TxOutConfirmationNumber, TxOutMembershipProof},
    BlockIndex,
};
use mc_transaction_std::{InputCredentials, TransactionBuilder};
use rand::Rng;
use std::{
    cmp::Reverse,
    convert::TryFrom,
    iter::{empty, FromIterator},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

/// Default number of blocks used for calculating transaction tombstone block number.
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

pub struct TransactionsManager<T: UserTxConnection + 'static> {
    /// Ledger database.
    ledger_db: LedgerDB,

    /// mobilecoind database.
    mobilecoind_db: Database,

    /// Peer manager, for communicating with validator nodes.
    peer_manager: ConnectionManager<T>,

    /// Logger.
    logger: Logger,

    /// Monotonically increasing counter. This is used for node round-robin selection.
    submit_node_offset: Arc<AtomicUsize>,
}

impl<T: UserTxConnection + 'static> Clone for TransactionsManager<T> {
    fn clone(&self) -> Self {
        Self {
            ledger_db: self.ledger_db.clone(),
            mobilecoind_db: self.mobilecoind_db.clone(),
            peer_manager: self.peer_manager.clone(),
            logger: self.logger.clone(),
            submit_node_offset: self.submit_node_offset.clone(),
        }
    }
}

impl<T: UserTxConnection + 'static> TransactionsManager<T> {
    pub fn new(
        ledger_db: LedgerDB,
        mobilecoind_db: Database,
        peer_manager: ConnectionManager<T>,
        logger: Logger,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            ledger_db,
            mobilecoind_db,
            peer_manager,
            logger,
            submit_node_offset: Arc::new(AtomicUsize::new(rng.next_u64() as usize)),
        }
    }

    pub fn build_transaction(
        &self,
        sender_monitor_id: &MonitorId,
        change_subaddress: u64,
        inputs: &[UnspentTxOut],
        outlays: &[Outlay],
        opt_fee: u64,
        opt_tombstone: u64,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(o!("sender_monitor_id" => sender_monitor_id.to_string(), "outlays" => format!("{:?}", outlays)));
        log::trace!(logger, "Building pending transaction...");

        // TODO fog service is currently unsupported.
        assert!(!outlays
            .iter()
            .any(|outlay| outlay.receiver.fog_report_url().is_some()));

        // Must have at least one output
        if outlays.is_empty() {
            return Err(Error::TxBuildError(
                "Must have at least one destination".into(),
            ));
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

        // Figure out the fee.
        let fee = if opt_fee > 0 { opt_fee } else { MINIMUM_FEE };

        // Select the UTXOs to be used for this transaction.
        let selected_utxos =
            Self::select_utxos_for_value(inputs, total_value + fee, MAX_INPUTS as usize)?;
        log::trace!(
            logger,
            "Selected {} utxos ({:?})",
            selected_utxos.len(),
            selected_utxos,
        );

        // Get membership proofs for selected utxos.
        let selected_utxos_with_proofs = self.get_membership_proofs(selected_utxos.clone())?;
        log::trace!(logger, "Got membership proofs");

        // Get rings.
        // TODO configurable ring size
        let excluded_tx_out_indices: Vec<u64> = selected_utxos
            .iter()
            .map(|utxo| {
                self.ledger_db
                    .get_tx_out_index_by_hash(&utxo.tx_out.hash())
                    .map_err(Error::LedgerDB)
            })
            .collect::<Result<Vec<u64>, Error>>()?;

        let rings = self.get_rings(
            DEFAULT_RING_SIZE,
            selected_utxos_with_proofs.len(),
            &excluded_tx_out_indices,
        )?;
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
            fee,
            &sender_monitor_data.account_key,
            change_subaddress,
            outlays,
            tombstone_block,
            &mut rng,
            &self.logger,
        )?;
        log::trace!(logger, "Tx constructed, hash={}", tx_proposal.tx.tx_hash());

        Ok(tx_proposal)
    }

    pub fn generate_optimization_tx(
        &self,
        monitor_id: &MonitorId,
        subaddress_index: u64,
    ) -> Result<TxProposal, Error> {
        let logger = self.logger.new(
            o!("monitor_id" => monitor_id.to_string(), "subaddress_index" => subaddress_index),
        );
        log::trace!(logger, "Generating optimization transaction...");

        // Get monitor data.
        let monitor_data = self.mobilecoind_db.get_monitor_data(monitor_id)?;

        // Select UTXOs.
        let num_blocks_in_ledger = self.ledger_db.num_blocks()?;

        let inputs = self
            .mobilecoind_db
            .get_utxos_for_subaddress(monitor_id, subaddress_index)?;
        let (selected_utxos, fee) = Self::select_utxos_for_optimization(
            num_blocks_in_ledger,
            &inputs,
            MAX_INPUTS as usize,
        )?;

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

        // Get membership proofs for selected utxos.
        let selected_utxos_with_proofs = self.get_membership_proofs(selected_utxos.clone())?;
        log::trace!(logger, "Got membership proofs");

        // Get rings.
        // TODO configurable ring size
        let excluded_tx_out_indices: Vec<u64> = selected_utxos
            .iter()
            .map(|utxo| {
                self.ledger_db
                    .get_tx_out_index_by_hash(&utxo.tx_out.hash())
                    .map_err(Error::LedgerDB)
            })
            .collect::<Result<Vec<u64>, Error>>()?;

        let rings = self.get_rings(
            DEFAULT_RING_SIZE,
            selected_utxos_with_proofs.len(),
            &excluded_tx_out_indices,
        )?;
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
            fee,
            &monitor_data.account_key,
            subaddress_index,
            &outlays,
            tombstone_block,
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

    /// Submit a previously built tx proposal to the network.
    pub fn submit_tx_proposal(&self, tx_proposal: &TxProposal) -> Result<u64, Error> {
        // Pick a peer to submit to.
        let idx = self.submit_node_offset.fetch_add(1, Ordering::SeqCst);
        let responder_ids = self.peer_manager.responder_ids();
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
        utxos: &[UnspentTxOut],
        value: u64,
        max_inputs: usize,
    ) -> Result<Vec<UnspentTxOut>, Error> {
        // Sort the utxos in descending order by value.
        let mut sorted_utxos = utxos.to_vec();
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

    /// Select UTXOs for optimization. The current strategy is to to attempt to add the maximum number
    /// of small UTXOs into the biggest one, which is the one most likely to be used when spending.
    /// The assumption is that if we maintain it as the biggest, we're less likely to need multiple
    /// UTXOs in future transactions.
    /// 1) Filter out UTXOs which we believe are currently still pending/at an unknown state.
    /// 2) Sort remaining UTXOs in ascending order (by their value).
    /// 3) Grab the largest available UTXO, and MAX_INPUTS-1 smallest available UTXOs.
    /// 4) If the sum of the smallest available UTXOs > fee, we would be able to increase our largest
    ///    UTXO and we're done. If not, try again without the smallest UTXO.
    ///
    /// Returns a tuple of (selected UTXOs, fee).
    fn select_utxos_for_optimization(
        num_blocks_in_ledger: u64,
        inputs: &[UnspentTxOut],
        max_inputs: usize,
    ) -> Result<(Vec<UnspentTxOut>, u64), Error> {
        if max_inputs < 2 {
            return Err(Error::InvalidArgument(
                "max_inputs".to_owned(),
                "need at least 2 inputs to be able to merge".to_owned(),
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
            // If there are no spendable inputs, we've tried merging all of them and still ended up losing it all to fees.
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

            // Calculate the fee - right now this is constant.
            let fee = MINIMUM_FEE;

            // See if the total amount we are trying to merge into our biggest UTXO is bigger than the fee.
            // If it's smaller, the merge would just lose us money.
            if total > fee {
                // Grab the UTXO we are merging into and stop iterating.
                selected_utxos.push(biggest_utxo);

                // Sanity - the amount we're moving sans the fee needs to increase the value of our biggest UTXO.
                let total_value: u64 = selected_utxos.iter().map(|utxo| utxo.value).sum();
                assert!(total_value - fee > biggest_utxo.value);

                // Return our selected utxos and fee.
                return Ok((selected_utxos.into_iter().cloned().collect(), fee));
            }

            // Merging the currently selected set of UTXOs would lose us money. Try again without the smallest UTXO.
            spendable_inputs.remove(0);
        }
    }

    /// Get membership proofs for a list of UTXOs.
    fn get_membership_proofs(
        &self,
        utxos: Vec<UnspentTxOut>,
    ) -> Result<Vec<(UnspentTxOut, TxOutMembershipProof)>, Error> {
        let indexes = utxos
            .iter()
            .map(|utxo| self.ledger_db.get_tx_out_index_by_hash(&utxo.tx_out.hash()))
            .collect::<Result<Vec<u64>, LedgerError>>()?;
        let proofs = self.ledger_db.get_tx_out_proof_of_memberships(&indexes)?;

        Ok(utxos.into_iter().zip(proofs.into_iter()).collect())
    }

    /// Get rings.
    fn get_rings(
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

        // Randomly sample `num_requested` TxOuts, without replacement and convert into a Vec<u64>
        let mut rng = rand::thread_rng();
        let mut sampled_indices: HashSet<u64> = HashSet::default();
        while sampled_indices.len() < num_requested {
            let index = rng.gen_range(0, num_txos);
            if excluded_tx_out_indices.contains(&index) {
                continue;
            }
            sampled_indices.insert(index);
        }
        let sampled_indices_vec: Vec<u64> = sampled_indices.into_iter().collect();

        // Get proofs for all of those indexes.
        let proofs = self
            .ledger_db
            .get_tx_out_proof_of_memberships(&sampled_indices_vec)?;

        // Create an iterator that returns (index, proof) elements.
        let mut indexes_and_proofs_iterator =
            sampled_indices_vec.into_iter().zip(proofs.into_iter());

        // Convert that into a Vec<Vec<TxOut, TxOutMembershipProof>>
        let mut rings_with_proofs = Vec::new();

        for _ in 0..num_rings {
            let mut ring = Vec::new();
            for _ in 0..ring_size {
                let (index, proof) = indexes_and_proofs_iterator.next().unwrap();
                let tx_out = self.ledger_db.get_tx_out_by_index(index)?;

                ring.push((tx_out, proof));
            }
            rings_with_proofs.push(ring);
        }

        Ok(rings_with_proofs)
    }

    /// Build a TxProposal object.
    fn build_tx_proposal(
        inputs: &[(UnspentTxOut, TxOutMembershipProof)],
        rings: Vec<Vec<(TxOut, TxOutMembershipProof)>>,
        fee: u64,
        from_account_key: &AccountKey,
        change_subaddress: u64,
        destinations: &[Outlay],
        tombstone_block: BlockIndex,
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
            return Err(Error::TxBuildError(err));
        }

        // Check that we have at least one destination.
        if destinations.is_empty() {
            return Err(Error::TxBuildError(
                "Must have at least one destination".into(),
            ));
        }

        // Create tx_builder.
        let mut tx_builder = TransactionBuilder::new();

        tx_builder.set_fee(fee);

        // Unzip each vec of tuples into a tuple of vecs.
        let mut rings_and_proofs: Vec<(Vec<TxOut>, Vec<TxOutMembershipProof>)> = rings
            .into_iter()
            .map(|tuples| tuples.into_iter().unzip())
            .collect();

        // Add inputs to the tx.
        for (utxo, proof) in inputs {
            let (mut ring, mut membership_proofs) = rings_and_proofs
                .pop()
                .ok_or_else(|| Error::TxBuildError("rings_and_proofs was empty".to_string()))?;
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
                    // The real input is always the first element. This is safe because TransactionBuilder
                    // sorts each ring.
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
                .map_err(|_| Error::TxBuildError("failed creating InputCredentials".into()))?,
            );
        }

        // Add outputs to our destinations.
        let mut total_value = 0;
        let mut tx_out_to_outlay_index = HashMap::default();
        let mut outlay_confirmation_numbers = Vec::default();
        for (i, outlay) in destinations.iter().enumerate() {
            let (tx_out, confirmation_number) = tx_builder
                .add_output(outlay.value, &outlay.receiver, None, rng)
                .map_err(|err| Error::TxBuildError(format!("failed adding output: {}", err)))?;

            tx_out_to_outlay_index.insert(tx_out, i);
            outlay_confirmation_numbers.push(confirmation_number);

            total_value += outlay.value;
        }

        // Figure out if we have change.
        let input_value = inputs
            .iter()
            .fold(0, |acc, (utxo, _proof)| acc + utxo.value);
        if total_value > input_value {
            return Err(Error::InsufficientFunds);
        }
        let change = input_value - total_value - tx_builder.fee;

        // If we do, add an output for that as well.
        if change > 0 {
            tx_builder
                .add_output(
                    change,
                    &from_account_key.subaddress(change_subaddress),
                    None,
                    rng,
                )
                .map_err(|err| {
                    Error::TxBuildError(format!("failed adding output (change): {}", err))
                })?;
        }

        // Set tombstone block.
        tx_builder.set_tombstone_block(tombstone_block);

        // Build tx.
        let tx = tx_builder
            .build(rng)
            .map_err(|err| Error::TxBuildError(format!("build tx failed: {}", err)))?;

        // Map each TxOut in the constructed transaction to its respective outlay.
        let outlay_index_to_tx_out_index =
            HashMap::from_iter(tx.prefix.outputs.iter().enumerate().filter_map(
                |(tx_out_index, tx_out)| {
                    if let Some(outlay_index) = tx_out_to_outlay_index.get(tx_out) {
                        Some((*outlay_index, tx_out_index))
                    } else {
                        None
                    }
                },
            ));

        // Sanity check: All of our outlays should have a unique index in the map.
        assert_eq!(outlay_index_to_tx_out_index.len(), destinations.len());
        let mut found_tx_out_indices = HashSet::default();
        for i in 0..destinations.len() {
            let tx_out_index = outlay_index_to_tx_out_index
                .get(&i)
                .expect("index not in map");
            if !found_tx_out_indices.insert(tx_out_index) {
                panic!("duplicate index {} found in map", tx_out_index);
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

#[cfg(test)]
mod test {
    use super::*;
    use mc_connection::ThickClient;
    use mc_crypto_keys::RistrettoPrivate;
    use mc_transaction_core::constants::MILLIMOB_TO_PICOMOB;
    use mc_util_from_random::FromRandom;
    use rand::{rngs::StdRng, SeedableRng};

    fn generate_utxos(num_utxos: usize) -> Vec<UnspentTxOut> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let alice = AccountKey::random(&mut rng);
        let tx_secret_key_for_txo = RistrettoPrivate::from_random(&mut rng);

        let tx_out = TxOut::new(
            1,
            &alice.default_subaddress(),
            &tx_secret_key_for_txo,
            Default::default(),
            &mut rng,
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
        let selected_utxos =
            TransactionsManager::<ThickClient>::select_utxos_for_value(&utxos, 300, utxos.len())
                .unwrap();

        assert_eq!(selected_utxos, vec![utxos[0].clone(), utxos[1].clone()]);

        // Sending 301 should select 100 + 200 + 300 when 3 inputs are allowed.
        let selected_utxos =
            TransactionsManager::<ThickClient>::select_utxos_for_value(&utxos, 301, utxos.len())
                .unwrap();

        assert_eq!(
            selected_utxos,
            vec![utxos[0].clone(), utxos[1].clone(), utxos[2].clone()]
        );

        // Sending 301 should select 200 + 300 when only 2  inputs are allowed.
        let selected_utxos =
            TransactionsManager::<ThickClient>::select_utxos_for_value(&utxos, 301, 2).unwrap();

        assert_eq!(selected_utxos, vec![utxos[1].clone(), utxos[2].clone()]);
    }

    #[test]
    fn test_select_utxos_for_value_errors_if_too_many_inputs_are_needed() {
        let utxos = generate_utxos(10);
        // While we have enough utxos to sum to 5, if the input limit is 4 we should fail.
        match TransactionsManager::<ThickClient>::select_utxos_for_value(&utxos, 5, 4) {
            Err(Error::InsufficientFundsFragmentedUtxos) => {
                // Expected.
            }
            _ => panic!("Did not get expected error"),
        };
    }

    #[test]
    fn test_select_utxos_for_value_errors_if_insufficient_funds() {
        let utxos = generate_utxos(10);
        // While we have enough utxos to sum to 5, if the input limit is 4 we should fail.
        match TransactionsManager::<ThickClient>::select_utxos_for_value(&utxos, 50, 100) {
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

            let (selected_utxos, fee) =
                TransactionsManager::<ThickClient>::select_utxos_for_optimization(1000, &utxos, 2)
                    .unwrap();

            assert_eq!(selected_utxos, vec![utxos[0].clone(), utxos[4].clone()]);
            assert_eq!(fee, MINIMUM_FEE);
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

            let (selected_utxos, fee) =
                TransactionsManager::<ThickClient>::select_utxos_for_optimization(1000, &utxos, 3)
                    .unwrap();

            assert_eq!(
                selected_utxos,
                vec![utxos[0].clone(), utxos[2].clone(), utxos[4].clone()]
            );
            assert_eq!(fee, MINIMUM_FEE);
        }
    }

    // Test behavior around the fee amount (off by one, exact fee, etc).
    #[test]
    fn test_select_utxos_for_optimization_behavior_around_fee() {
        // When the sum of available UTXOs is lower than the fee, no merging will take place.
        {
            let mut utxos = generate_utxos(6);

            utxos[0].value = 1 * MILLIMOB_TO_PICOMOB;
            utxos[1].value = 1 * MILLIMOB_TO_PICOMOB;
            utxos[2].value = 1 * MILLIMOB_TO_PICOMOB;
            utxos[3].value = 1 * MILLIMOB_TO_PICOMOB;
            utxos[4].value = 2000 * MILLIMOB_TO_PICOMOB;
            utxos[5].value = 1 * MILLIMOB_TO_PICOMOB;

            assert!(
                utxos[0].value + utxos[1].value + utxos[2].value + utxos[3].value + utxos[5].value
                    < MINIMUM_FEE
            );

            let result = TransactionsManager::<ThickClient>::select_utxos_for_optimization(
                1000, &utxos, 100,
            );
            assert!(result.is_err());
        }

        // When the sum of available UTXOs is exactly equal the fee amount, no merging will ltake place.
        {
            let mut utxos = generate_utxos(2);

            utxos[0].value = MINIMUM_FEE;
            utxos[1].value = 2000 * MILLIMOB_TO_PICOMOB;

            let result = TransactionsManager::<ThickClient>::select_utxos_for_optimization(
                1000, &utxos, 100,
            );
            assert!(result.is_err());
        }

        // When the sum if available UTXOs is higher than the fee, merging is possible.
        {
            let mut utxos = generate_utxos(4);

            utxos[0].value = MINIMUM_FEE;
            utxos[1].value = 2000 * MILLIMOB_TO_PICOMOB;
            utxos[2].value = 1 * MILLIMOB_TO_PICOMOB;
            utxos[3].value = 2 * MILLIMOB_TO_PICOMOB;

            let (selected_utxos, fee) =
                TransactionsManager::<ThickClient>::select_utxos_for_optimization(1000, &utxos, 3)
                    .unwrap();
            // Since we're limited to 3 inputs, the lowest input (of value 1) is going to get excluded.
            assert_eq!(
                selected_utxos,
                vec![utxos[3].clone(), utxos[0].clone(), utxos[1].clone()]
            );
            assert_eq!(fee, MINIMUM_FEE);
        }
    }

    // Attempting to select from a set of less than 2 UTXOs should fail
    #[test]
    fn test_select_utxos_for_optimizations_errors_on_less_than_2_utxos() {
        let mut utxos = generate_utxos(2);

        utxos[0].value = 2000 * MILLIMOB_TO_PICOMOB;
        utxos[1].value = 2000 * MILLIMOB_TO_PICOMOB;

        let result =
            TransactionsManager::<ThickClient>::select_utxos_for_optimization(1000, &[], 100);
        assert!(result.is_err());

        let result = TransactionsManager::<ThickClient>::select_utxos_for_optimization(
            1000,
            &utxos[0..1],
            100,
        );
        assert!(result.is_err());

        // A set of 2 utxos succeeds when max inputs is 2, but fails when it is 3 (since there's no point to merge 2 when we can directly spend 3)
        let result = TransactionsManager::<ThickClient>::select_utxos_for_optimization(
            1000,
            &utxos[0..2],
            2,
        );
        assert!(result.is_ok());

        let result = TransactionsManager::<ThickClient>::select_utxos_for_optimization(
            1000,
            &utxos[0..2],
            3,
        );
        assert!(result.is_err());
    }
}
