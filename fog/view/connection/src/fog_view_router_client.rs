// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Makes dummy requests to the fog view router service

use futures::{SinkExt, TryStreamExt};
use grpcio::{ChannelBuilder, Environment};
use mc_attest_api::attest::Message;
use mc_common::logger::{log, o, Logger};
use mc_fog_api::{view::FogViewRouterRequest, view_grpc::FogViewRouterApiClient};
use mc_fog_uri::FogViewRouterUri;
use mc_util_grpc::ConnectionUriGrpcioChannel;
use std::sync::Arc;

/// A high-level object mediating requests to the fog view router service
pub struct FogViewRouterGrpcClient {
    /// The fog view router grpc client
    fog_view_router_client: FogViewRouterApiClient,
    /// A logger object
    logger: Logger,
}

impl FogViewRouterGrpcClient {
    /// Creates a new fog view router grpc client
    ///
    /// Arguments:
    /// * uri: The Uri to connect to
    /// * env: A grpc environment (thread pool) to use for this connection
    /// * logger: For logging
    pub fn new(uri: FogViewRouterUri, env: Arc<Environment>, logger: Logger) -> Self {
        let logger = logger.new(o!("mc.fog.view.router.uri" => uri.to_string()));

        let ch = ChannelBuilder::default_channel_builder(env).connect_to_uri(&uri, &logger);

        let fog_view_router_client = FogViewRouterApiClient::new(ch);

        Self {
            fog_view_router_client,
            logger,
        }
    }

    /// Makes streaming requests to the fog view router service.
    pub async fn request(&self) -> Result<(), grpcio::Error> {
        let (mut sink, mut receiver) = self.fog_view_router_client.request()?;
        let attested_message = Message::new();
        let mut request = FogViewRouterRequest::new();
        request.set_query(attested_message);
        let send = async move {
            for i in 0..5 {
                log::info!(self.logger, "Sending message {}", i);
                sink.send((request.clone(), grpcio::WriteFlags::default()))
                    .await?;
            }
            sink.close().await?;
            Ok(()) as Result<(), grpcio::Error>
        };

        let receive = async move {
            let mut counter = 0;
            while (receiver.try_next().await?).is_some() {
                counter += 1;
                log::info!(self.logger, "Got message {} ", counter);
            }
            Ok(())
        };
        let (sr, rr) = futures::join!(send, receive);
        sr.and(rr)
    }
}
