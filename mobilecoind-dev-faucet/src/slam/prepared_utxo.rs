// Copyright (c) 2018-2022 The MobileCoin Foundation

use super::{SlamParams, UtxoRecord};
use mc_account_keys::{AccountKey, PublicAddress};
use mc_api::ConversionError;
use mc_attest_verifier::Verifier;
use mc_common::logger::{log, Logger};
use mc_crypto_ring_signature_signer::{LocalRingSigner, OneTimeKeyDeriveData};
use mc_fog_report_validation::FogResolver;
use mc_mobilecoind_api::{mobilecoind_api_grpc::MobilecoindApiClient, GetNetworkStatusResponse};
use mc_transaction_core::{
    constants::RING_SIZE,
    tx::{Tx, TxOut, TxOutMembershipProof},
    Amount, BlockVersion, TokenId,
};
use mc_transaction_std::{EmptyMemoBuilder, InputCredentials, TransactionBuilder};
use protobuf::RepeatedField;
use rand::thread_rng;

/// A UTXO that has been prepared for transaction building, by collecting
/// membership proofs and ring members.
pub struct PreparedUtxo {
    /// The number associated to this utxo for logging
    pub index: usize,
    /// A Utxo record from the faucet worker
    pub utxo_record: UtxoRecord,
    /// Ring of outputs
    pub ring: Vec<TxOut>,
    /// Membership proofs
    pub membership_proofs: Vec<TxOutMembershipProof>,
    /// Real input index
    pub real_input_index: usize,
}

impl PreparedUtxo {
    /// Make a new prepared utxo
    ///
    /// Start with a UtxoRecord, and get proofs and mixins from mobilecoind
    pub async fn new(
        index: usize,
        utxo_record: UtxoRecord,
        params: &SlamParams,
        mobilecoind_api_client: &MobilecoindApiClient,
        logger: &Logger,
    ) -> Result<PreparedUtxo, String> {
        let mut tries = 1;
        let (proofs_resp, mixins_resp) = loop {
            match Self::get_proofs_and_mixins(&utxo_record, mobilecoind_api_client).await {
                Ok(result) => {
                    break result;
                }
                Err(err) => {
                    log::debug!(
                        logger,
                        "Preparing tx #{} (attempt {}/{}) : {}",
                        index,
                        tries,
                        params.retries,
                        err
                    );
                    if tries == params.retries {
                        log::error!(
                            logger,
                            "Failed preparing tx #{} on {} tries: {}",
                            index,
                            params.retries,
                            err
                        );
                        return Err(err);
                    }
                    tokio::time::sleep(params.retry_period).await;
                }
            }
            tries += 1;
        };

        // The Tx builder sorts the ring anyways, so it doesn't matter if we always put
        // the real input first.
        let (ring, membership_proofs): (Vec<TxOut>, Vec<TxOutMembershipProof>) = proofs_resp
            .get_output_list()
            .iter()
            .chain(mixins_resp.get_mixins().iter())
            .map(|tx_out_with_proof| {
                Ok((
                    tx_out_with_proof.get_output().try_into()?,
                    tx_out_with_proof.get_proof().try_into()?,
                ))
            })
            .collect::<Result<Vec<_>, ConversionError>>()
            .map_err(|err| format!("Conversion error: {}", err))?
            .into_iter()
            .unzip();

        Ok(PreparedUtxo {
            index,
            utxo_record,
            ring,
            membership_proofs,
            real_input_index: 0,
        })
    }

    async fn get_proofs_and_mixins(
        utxo_record: &UtxoRecord,
        mobilecoind_api_client: &MobilecoindApiClient,
    ) -> Result<
        (
            mc_mobilecoind_api::GetMembershipProofsResponse,
            mc_mobilecoind_api::GetMixinsResponse,
        ),
        String,
    > {
        // Get a membership proof for this utxo
        let mut req = mc_mobilecoind_api::GetMembershipProofsRequest::new();
        req.set_outputs(RepeatedField::from(vec![utxo_record
            .utxo
            .get_tx_out()
            .clone()]));

        let proofs_resp = mobilecoind_api_client
            .get_membership_proofs_async(&req)
            .map_err(|err| format!("Failed to request membership proofs: {}", err))?
            .await
            .map_err(|err| format!("Request membership proofs ended in error: {}", err))?;

        // Get mixins for this utxo
        let mut req = mc_mobilecoind_api::GetMixinsRequest::new();
        req.set_num_mixins(RING_SIZE as u64 - 1);
        req.set_excluded(RepeatedField::from(vec![utxo_record
            .utxo
            .get_tx_out()
            .clone()]));

        let mixins_resp = mobilecoind_api_client
            .get_mixins_async(&req)
            .map_err(|err| format!("Failed to request mixins: {}", err))?
            .await
            .map_err(|err| format!("Request mixins ended in error: {}", err))?;

        Ok((proofs_resp, mixins_resp))
    }

    /// Build a Tx from a prepared utxo
    pub fn build_tx(
        &self,
        tombstone_block: u64,
        recipient: &PublicAddress,
        account_key: &AccountKey,
        network_state: &GetNetworkStatusResponse,
    ) -> Result<Tx, String> {
        let mut rng = thread_rng();
        // Get block version to target
        let block_version =
            BlockVersion::try_from(network_state.get_last_block_info().network_block_version)
                .map_err(|err| format!("Block version: {}", err))?;

        // Get minimum fee for this token id
        let value = self.utxo_record.utxo.value;
        let token_id = self.utxo_record.utxo.token_id;
        let fee_value = *network_state
            .get_last_block_info()
            .minimum_fees
            .get(&token_id)
            .ok_or_else(|| format!("Missing fee for token id: {}", token_id))?;
        let token_id = TokenId::from(token_id);
        let fee_amount = Amount::new(fee_value, token_id);

        // Make a dummy fog resolver (we don't need to support slamming to fog address
        // because we are slamming ourself, at least at this revision)
        let fog_resolver = {
            let responses = Default::default();
            let report_verifier = Verifier::default();

            FogResolver::new(responses, &report_verifier)
                .map_err(|err| format!("Fog resolver: {}", err))?
        };

        // Create tx_builder.
        let mut tx_builder = TransactionBuilder::new(
            block_version,
            fee_amount,
            fog_resolver,
            EmptyMemoBuilder::default(),
        )
        .map_err(|err| format!("Transaction builder new: {}", err))?;

        tx_builder.set_tombstone_block(tombstone_block);
        tx_builder.add_input(self.get_input_credentials(account_key)?);
        tx_builder
            .add_output(
                Amount::new(value - fee_value, token_id),
                recipient,
                &mut rng,
            )
            .map_err(|err| format!("Add output: {}", err))?;

        tx_builder
            .build(&LocalRingSigner::from(account_key), &mut rng)
            .map_err(|err| format!("Build Tx: {}", err))
    }

    fn get_input_credentials(&self, account_key: &AccountKey) -> Result<InputCredentials, String> {
        let onetime_key_derive_data =
            OneTimeKeyDeriveData::SubaddressIndex(self.utxo_record.utxo.subaddress_index);
        InputCredentials::new(
            self.ring.clone(),
            self.membership_proofs.clone(),
            self.real_input_index,
            onetime_key_derive_data,
            *account_key.view_private_key(),
        )
        .map_err(|err| format!("InputCredentials: {}", err))
    }
}
