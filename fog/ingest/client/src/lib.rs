// Copyright (c) 2018-2021 The MobileCoin Foundation

pub mod config;
mod error;
use error::Error;

use grpcio::{ChannelBuilder, Environment};
use mc_common::logger::{log, o, Logger};
use mc_crypto_keys::CompressedRistrettoPublic;
use mc_fog_api::{
    empty::Empty,
    ingest::{ReportLostIngressKeyRequest, SetPubkeyExpiryWindowRequest},
    ingest_common::{IngestSummary, SetPeersRequest},
    ingest_grpc::AccountIngestApiClient,
};
use mc_fog_types::common::BlockRange;
use mc_fog_uri::FogIngestUri;
use mc_util_grpc::{BasicCredentials, ConnectionUriGrpcioChannel};
use mc_util_uri::ConnectionUri;
use protobuf::RepeatedField;
use retry::{retry, Error as RetryError};
use std::{convert::TryFrom, sync::Arc, time::Duration};

/// Fog ingest GRPC client.
pub struct FogIngestGrpcClient {
    /// The underlying GRPC client.
    ingest_api_client: AccountIngestApiClient,

    /// Authentication credentials derived from the uri.
    creds: BasicCredentials,

    /// Retry parameter: How long we retry for
    retry_duration: Duration,

    /// Logger.
    logger: Logger,
}

// The error exposed from this module is RetryError wrapping the lower-level
// error
pub type ClientResult<T> = core::result::Result<T, RetryError<Error>>;

impl FogIngestGrpcClient {
    pub fn new(
        uri: FogIngestUri,
        retry_duration: Duration,
        env: Arc<Environment>,
        logger: Logger,
    ) -> Self {
        let logger = logger.new(o!("mc.fog.cxn" => uri.to_string()));

        let creds = BasicCredentials::new(&uri.username(), &uri.password());

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let ingest_api_client = AccountIngestApiClient::new(ch);

        Self {
            ingest_api_client,
            creds,
            retry_duration,
            logger,
        }
    }

    pub fn get_status(&self) -> ClientResult<IngestSummary> {
        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .get_status_opt(&Empty::new(), self.creds.call_option()?)?)
        })
    }

    pub fn new_keys(&self) -> ClientResult<IngestSummary> {
        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .new_keys_opt(&Empty::default(), self.creds.call_option()?)?)
        })
    }

    pub fn set_pubkey_expiry_window(
        &self,
        pubkey_expiry_window: u64,
    ) -> ClientResult<IngestSummary> {
        let mut req = SetPubkeyExpiryWindowRequest::new();
        req.set_pubkey_expiry_window(pubkey_expiry_window);

        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .set_pubkey_expiry_window_opt(&req, self.creds.call_option()?)?)
        })
    }

    pub fn set_peers(&self, peer_uris: &[String]) -> ClientResult<IngestSummary> {
        let mut req = SetPeersRequest::new();
        req.set_ingest_peer_uris(RepeatedField::from_vec(peer_uris.to_vec()));

        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .set_peers_opt(&req, self.creds.call_option()?)?)
        })
    }

    pub fn activate(&self) -> ClientResult<IngestSummary> {
        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .activate_opt(&Empty::default(), self.creds.call_option()?)?)
        })
    }

    pub fn retire(&self) -> ClientResult<IngestSummary> {
        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .retire_opt(&Empty::default(), self.creds.call_option()?)?)
        })
    }

    pub fn unretire(&self) -> ClientResult<IngestSummary> {
        retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .unretire_opt(&Empty::default(), self.creds.call_option()?)?)
        })
    }

    pub fn report_lost_ingress_key(&self, key: CompressedRistrettoPublic) -> ClientResult<()> {
        log::trace!(self.logger, "report_lost_ingress_key({})", key,);

        let mut req = ReportLostIngressKeyRequest::new();
        req.set_key((&key).into());

        let _ = retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .report_lost_ingress_key_opt(&req, self.creds.call_option()?)?)
        })?;

        Ok(())
    }

    pub fn get_pubkey(&self) -> ClientResult<CompressedRistrettoPublic> {
        let resp = retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .get_status_opt(&Empty::new(), self.creds.call_option()?)?)
        })?;

        Ok(
            CompressedRistrettoPublic::try_from(resp.get_ingress_pubkey())
                .expect("Got back invalid compressed ristretto point"),
        )
    }

    pub fn get_missed_block_ranges(&self) -> ClientResult<Vec<BlockRange>> {
        log::trace!(self.logger, "get_missed_block_ranges()");

        let resp = retry(self.get_retries(), || -> Result<_, Error> {
            Ok(self
                .ingest_api_client
                .get_missed_block_ranges_opt(&Empty::default(), self.creds.call_option()?)?)
        })?;

        Ok(resp
            .get_missed_block_ranges()
            .iter()
            .map(|range| BlockRange::new(range.start_block, range.end_block))
            .collect())
    }

    // The retry crate works by taking an iterator over durations, and a closure
    // This function returns the iterator over durations consistent with configured
    // policy, which is then used to implement retries for all the grpc calls
    fn get_retries(&self) -> Box<dyn Iterator<Item = Duration>> {
        Box::new(
            retry::delay::Fixed::from_millis(100).take(self.retry_duration.as_secs() as usize * 10),
        )
    }
}
