// Copyright (c) 2018-2021 The MobileCoin Foundation

use grpcio::{RpcContext, RpcStatus, UnarySink};
use mc_attest_api::attest::{AuthMessage, Message};
use mc_attest_enclave_api::ClientSession;
use mc_common::logger::{log, Logger};
use mc_fog_api::{ledger::OutputResultCode, ledger_grpc::FogMerkleProofApi};
use mc_fog_ledger_enclave::{GetOutputsResponse, LedgerEnclaveProxy, OutputContext, OutputResult};
use mc_fog_ledger_enclave_api::Error as EnclaveError;
use mc_ledger_db::{self, Error as DbError, Ledger};
use mc_transaction_core::tx::{TxOut, TxOutMembershipProof};
use mc_util_grpc::{
    rpc_database_err, rpc_internal_error, rpc_invalid_arg_error, rpc_logger, rpc_permissions_error,
    send_result, Authenticator,
};
use mc_util_metrics::SVC_COUNTERS;
use std::{convert::From, sync::Arc};

// Maximum number of TxOuts that may be returned for a single request.
pub const MAX_REQUEST_SIZE: usize = 2000;

#[derive(Clone)]
pub struct MerkleProofService<L: Ledger + Clone, E: LedgerEnclaveProxy> {
    ledger: L,
    enclave: E,
    authenticator: Arc<dyn Authenticator + Send + Sync>,
    logger: Logger,
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> MerkleProofService<L, E> {
    pub fn new(
        ledger: L,
        enclave: E,
        authenticator: Arc<dyn Authenticator + Send + Sync>,
        logger: Logger,
    ) -> Self {
        Self {
            ledger,
            enclave,
            authenticator,
            logger,
        }
    }

    fn get_outputs_auth(&mut self, request: Message) -> Result<Message, RpcStatus> {
        mc_common::trace_time!(self.logger, "Get Outputs");

        let output_context = match self.enclave.get_outputs(request.clone().into()) {
            Ok(context) => context,
            Err(EnclaveError::Attest(attest_error)) => {
                return Err(rpc_permissions_error(
                    "get_outputs",
                    EnclaveError::Attest(attest_error),
                    &self.logger,
                ))
            }
            Err(EnclaveError::Serialization) => {
                return Err(rpc_invalid_arg_error(
                    "get_outputs",
                    EnclaveError::Serialization,
                    &self.logger,
                ))
            }
            Err(e) => return Err(rpc_internal_error("get_outputs", e, &self.logger)),
        };

        let output_data = self.get_outputs_impl(output_context)?;

        let result = match self
            .enclave
            .get_outputs_data(output_data, ClientSession::from(request.channel_id))
        {
            Ok(context) => context,
            Err(EnclaveError::Attest(attest_error)) => {
                return Err(rpc_permissions_error(
                    "get_outputs_data",
                    EnclaveError::Attest(attest_error),
                    &self.logger,
                ))
            }
            Err(EnclaveError::Serialization) => {
                return Err(rpc_invalid_arg_error(
                    "get_outputs_data",
                    EnclaveError::Serialization,
                    &self.logger,
                ))
            }
            Err(e) => return Err(rpc_internal_error("get_outputs_data", e, &self.logger)),
        };

        Ok(result.into())
    }

    fn get_outputs_impl(
        &mut self,
        output_context: OutputContext,
    ) -> Result<GetOutputsResponse, RpcStatus> {
        let num_requested = output_context.indexes.len();
        if num_requested > MAX_REQUEST_SIZE {
            return Err(rpc_invalid_arg_error(
                "get_outputs",
                "Request size exceeds limit",
                &self.logger,
            ));
        }

        Ok(GetOutputsResponse {
            num_blocks: self
                .ledger
                .num_blocks()
                .map_err(|err| rpc_database_err(err, &self.logger))?,
            global_txo_count: self
                .ledger
                .num_txos()
                .map_err(|err| rpc_database_err(err, &self.logger))?,
            results: output_context
                .indexes
                .iter()
                .map(|idx| -> Result<OutputResult, DbError> {
                    Ok(match self.get_output_impl(*idx)? {
                        Some((output, proof)) => OutputResult {
                            index: *idx,
                            result_code: OutputResultCode::Exists as u32,
                            output,
                            proof,
                        },
                        None => OutputResult {
                            index: *idx,
                            result_code: OutputResultCode::DoesNotExist as u32,
                            output: Default::default(),
                            proof: Default::default(),
                        },
                    })
                })
                .collect::<Result<Vec<_>, DbError>>()
                .map_err(|err| rpc_database_err(err, &self.logger))?,
        })
    }

    fn get_output_impl(
        &mut self,
        idx: u64,
    ) -> Result<Option<(TxOut, TxOutMembershipProof)>, DbError> {
        match self.ledger.get_tx_out_by_index(idx).and_then(|tx_out| {
            let proofs = self.ledger.get_tx_out_proof_of_memberships(&[idx])?;
            Ok(Some((tx_out, proofs[0].clone())))
        }) {
            Ok(result) => Ok(result),
            Err(DbError::NotFound) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl<L: Ledger + Clone, E: LedgerEnclaveProxy> FogMerkleProofApi for MerkleProofService<L, E> {
    fn get_outputs(&mut self, ctx: RpcContext, request: Message, sink: UnarySink<Message>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            send_result(ctx, sink, self.get_outputs_auth(request), &logger)
        })
    }

    fn auth(&mut self, ctx: RpcContext, request: AuthMessage, sink: UnarySink<AuthMessage>) {
        let _timer = SVC_COUNTERS.req(&ctx);
        mc_common::logger::scoped_global_logger(&rpc_logger(&ctx, &self.logger), |logger| {
            if let Err(err) = self.authenticator.authenticate_rpc(&ctx) {
                return send_result(ctx, sink, err.into(), &logger);
            }

            // TODO: Use the prost message directly, once available
            match self.enclave.client_accept(request.into()) {
                Ok((response, _session_id)) => {
                    send_result(ctx, sink, Ok(response.into()), &logger);
                }
                Err(client_error) => {
                    // This is debug because there's no requirement on the remote party to trigger
                    // it.
                    log::info!(
                        logger,
                        "LedgerEnclave::client_accept failed: {}",
                        client_error
                    );
                    // TODO: increment failed inbound peering counter.
                    send_result(
                        ctx,
                        sink,
                        Err(rpc_permissions_error(
                            "client_auth",
                            "Permission denied",
                            &logger,
                        )),
                        &logger,
                    );
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_account_keys::AccountKey;
    use mc_common::{
        logger::{test_with_logger, Logger},
        HashSet,
    };
    use mc_crypto_keys::{RistrettoPrivate, RistrettoPublic};
    use mc_fog_ledger_test_infra::{MockEnclave, MockLedger};
    use mc_transaction_core::{
        encrypted_fog_hint::{EncryptedFogHint, ENCRYPTED_FOG_HINT_LEN},
        membership_proofs::Range,
        onetime_keys::{create_onetime_public_key, create_shared_secret, create_tx_public_key},
        tx::{TxOut, TxOutMembershipElement, TxOutMembershipProof},
        Amount,
    };
    use mc_util_from_random::FromRandom;
    use mc_util_grpc::AnonymousAuthenticator;
    use rand::{rngs::StdRng, SeedableRng};

    /// Creates a number of TxOuts.
    ///
    /// All TxOuts are created as part of the same transaction, with the same
    /// recipient.
    fn get_tx_outs(num_tx_outs: u32) -> Vec<TxOut> {
        let mut rng: StdRng = SeedableRng::from_seed([1u8; 32]);
        let mut tx_outs: Vec<TxOut> = Vec::new();
        let tx_secret_key = RistrettoPrivate::from_random(&mut rng);
        let recipient_account = AccountKey::random(&mut rng);
        let value: u64 = 100;

        for output_index in 0..num_tx_outs {
            let recipient_account_default_subaddress = recipient_account.default_subaddress();
            let target_key =
                create_onetime_public_key(&tx_secret_key, &recipient_account_default_subaddress);
            let public_key = create_tx_public_key(
                &tx_secret_key,
                recipient_account_default_subaddress.spend_public_key(),
            );
            let shared_secret: RistrettoPublic = create_shared_secret(&target_key, &tx_secret_key);
            // FIXME: Without a different value, the txouts are identical - that
            // may be fine, or we may want a more robust mock ledger populator.
            let amount = Amount::new(value + output_index as u64, &shared_secret).unwrap();
            let tx_out = TxOut {
                amount,
                target_key: target_key.into(),
                public_key: public_key.into(),
                e_fog_hint: EncryptedFogHint::new(&[7u8; ENCRYPTED_FOG_HINT_LEN]),
                e_memo: None,
            };
            tx_outs.push(tx_out);
        }
        tx_outs
    }

    // `get_outputs` should return the correct number of distinct TxOuts.
    #[test_with_logger]
    fn test_get_outputs(logger: Logger) {
        // Initialize a mock ledger.
        let mut mock_ledger = MockLedger::default();

        let num_tx_outs: u32 = 100;
        let highest_index: u32 = num_tx_outs - 1;

        mock_ledger.num_tx_outs = num_tx_outs as u64;

        for (index, tx_out) in get_tx_outs(num_tx_outs).into_iter().enumerate() {
            mock_ledger.tx_out_by_index.insert(index as u64, tx_out);

            // Create a proof, using arbitrary hashes.
            let elements = vec![
                TxOutMembershipElement::new(Range::new(4, 4).unwrap(), [44u8; 32]),
                TxOutMembershipElement::new(Range::new(5, 5).unwrap(), [55u8; 32]),
            ];
            let proof =
                TxOutMembershipProof::new(index as u64, highest_index as u64, elements.clone());
            mock_ledger
                .tx_out_membership_proof_by_index
                .insert(index as u64, proof);
        }

        let enclave = MockEnclave::default();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut ledger_server_node =
            MerkleProofService::new(mock_ledger.clone(), enclave, authenticator, logger.clone());

        let request = OutputContext {
            indexes: (0..50).collect(),
            merkle_root_block: 0,
        };

        let output_data = ledger_server_node.get_outputs_impl(request).unwrap();

        // Response should contain the requested number of elements.
        assert_eq!(output_data.results.len(), 50);

        // Each element should contain a proof-of-membership.
        for i in 0..output_data.results.len() {
            let tx_out = output_data.results[i].output.clone();
            let proof = output_data.results[i].proof.clone();
            assert_eq!(proof.highest_index, highest_index as u64);

            // The proof should correspond to the TxOut it accompanies.
            let expected_tx_out: TxOut = mock_ledger.get_tx_out_by_index(proof.index).unwrap();
            assert_eq!(tx_out, expected_tx_out);

            // TODO: The proof should contain the correct hashes.
        }
    }

    // `get_outputs should return distinct elements`.
    #[test_with_logger]
    fn test_get_outputs_distinct_elements(logger: Logger) {
        // Initialize a mock ledger.
        let mut mock_ledger = MockLedger::default();
        let num_tx_outs: u32 = 100;
        mock_ledger.num_tx_outs = num_tx_outs as u64;

        // Populate the mock ledger with TxOuts and membership proofs.
        for (index, tx_out) in get_tx_outs(num_tx_outs).into_iter().enumerate() {
            mock_ledger.tx_out_by_index.insert(index as u64, tx_out);

            // Create a proof, using arbitrary hashes.
            let elements = vec![
                TxOutMembershipElement::new(Range::new(4, 4).unwrap(), [44u8; 32]),
                TxOutMembershipElement::new(Range::new(5, 5).unwrap(), [55u8; 32]),
            ];
            let proof =
                TxOutMembershipProof::new(index as u64, num_tx_outs as u64, elements.clone());
            mock_ledger
                .tx_out_membership_proof_by_index
                .insert(index as u64, proof);
        }

        let enclave = MockEnclave::default();
        let authenticator = Arc::new(AnonymousAuthenticator::default());
        let mut ledger_server_node =
            MerkleProofService::new(mock_ledger, enclave, authenticator, logger.clone());

        let request = OutputContext {
            indexes: (0..50).collect(),
            merkle_root_block: 0,
        };

        let output_data = ledger_server_node.get_outputs_impl(request).unwrap();

        // Response should contain distinct elements.
        let mut tx_out_set = HashSet::default();
        for data in output_data.results.iter() {
            tx_out_set.insert(data.output.clone());
        }
        assert_eq!(tx_out_set.len(), 50);
    }
}
