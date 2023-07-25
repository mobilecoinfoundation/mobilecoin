// Copyright (c) 2018-2023 The MobileCoin Foundation

//! Bits for correctly creating encrypted fog hints when minting

use grpcio::Environment;
use mc_account_keys::PublicAddress;
use mc_attestation_verifier::{TrustedIdentity, TrustedMrSignerIdentity};
use mc_common::logger::Logger;
use mc_fog_report_connection::GrpcFogReportConnection;
use mc_fog_report_resolver::FogResolver;
use mc_fog_report_validation::{FogPubkeyResolver, FullyValidatedFogPubkey};
use mc_rand::McRng;
use mc_sgx_css::Signature;
use mc_transaction_core::{encrypted_fog_hint::EncryptedFogHint, fog_hint::FogHint};
use mc_util_uri::FogUri;
use std::{str::FromStr, sync::Arc};

/// Data and objects needed to resolve a fog address and build an encrypted
/// fog hint in a one-off way appropriate for a CLI tool
pub struct FogContext {
    /// The chain id of the network we expect to connect to
    pub chain_id: String,
    /// The css file (loaded as signature) that we will verify report against
    pub css_signature: Signature,
    /// The grpcio environment
    pub grpc_env: Arc<Environment>,
    /// Logger
    pub logger: Logger,
}

impl FogContext {
    /// Get an encrypted fog hint for a TxOut belonging to a paritcular public
    /// address
    ///
    /// Arguments:
    /// * public_address
    ///
    /// Returns:
    /// * Encrypted fog hint
    /// * pubkey_expiry of the fog key that was used. This must bound the
    ///   tombstone block
    pub fn get_e_fog_hint(
        &self,
        public_address: &PublicAddress,
    ) -> Result<(EncryptedFogHint, u64), String> {
        let validated_fog_pubkey = self.resolve_one_fog_url(public_address)?;

        Ok((
            FogHint::from(public_address)
                .encrypt(&validated_fog_pubkey.pubkey, &mut McRng::default()),
            validated_fog_pubkey.pubkey_expiry,
        ))
    }

    /// Make a connection to fog report and get the fog reports for a particular
    /// public address. Then validate them against this public address' fog
    /// sig. Returns either a fully validated fog pubkey for this address,
    /// or an error.
    fn resolve_one_fog_url(
        &self,
        public_address: &PublicAddress,
    ) -> Result<FullyValidatedFogPubkey, String> {
        let fog_uri = FogUri::from_str(public_address.fog_report_url().ok_or("Missing fog url")?)
            .map_err(|err| format!("Invalid fog uri: {err}"))?;

        let conn = GrpcFogReportConnection::new(
            self.chain_id.clone(),
            self.grpc_env.clone(),
            self.logger.clone(),
        );

        let responses = conn
            .fetch_fog_reports([fog_uri].into_iter())
            .map_err(|err| format!("Error fetching fog reports: {err}"))?;

        let identity = fog_ingest_identity(self.css_signature.clone());
        let resolver = FogResolver::new(responses, [&identity])
            .map_err(|err| format!("Error building FogResolver: {err}"))?;
        resolver
            .get_fog_pubkey(public_address)
            .map_err(|err| format!("Could not validate fog pubkey: {err}"))
    }
}

fn fog_ingest_identity(signature: Signature) -> TrustedIdentity {
    let mr_signer_identity = TrustedMrSignerIdentity::new(
        signature.mrsigner().into(),
        signature.product_id().into(),
        signature.version(),
        [] as [&str; 0],
        &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"],
    );
    mr_signer_identity.into()
}
