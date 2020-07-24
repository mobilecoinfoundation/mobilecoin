// Copyright (c) 2018-2020 MobileCoin Inc.

//! Extension traits that make it easier to start GRPC servers and connect to them using URIs.

use grpcio::{
    Channel, ChannelBuilder, ChannelCredentialsBuilder, Environment, ServerBuilder,
    ServerCredentialsBuilder,
};
use mc_common::logger::{log, Logger};
use mc_util_uri::ConnectionUri;
use std::{sync::Arc, time::Duration};

/// A trait to ease grpcio channel construction from URIs.
pub trait ConnectionUriGrpcioChannel {
    /// Construct a ChannelBuilder with some sane defaults.
    fn default_channel_builder(env: Arc<Environment>) -> ChannelBuilder {
        ChannelBuilder::new(env)
            .keepalive_permit_without_calls(true)
            .keepalive_time(Duration::from_secs(1))
            .keepalive_timeout(Duration::from_secs(20))
            .max_reconnect_backoff(Duration::from_millis(2000))
            .initial_reconnect_backoff(Duration::from_millis(1000))
    }

    /// Connects a ChannelBuilder using a URI.
    fn connect_to_uri(self, uri: &impl ConnectionUri, logger: &Logger) -> Channel;
}

impl ConnectionUriGrpcioChannel for ChannelBuilder {
    fn connect_to_uri(mut self, uri: &impl ConnectionUri, logger: &Logger) -> Channel {
        if uri.use_tls() {
            if let Some(host_override) = uri.tls_hostname_override() {
                self = self.override_ssl_target(host_override);
            }

            let creds = match uri.ca_bundle().expect("failed getting ca bundle") {
                Some(cert) => ChannelCredentialsBuilder::new().root_cert(cert).build(),
                None => ChannelCredentialsBuilder::new().build(),
            };

            log::debug!(logger, "Creating secure gRPC connection to {}", uri.addr(),);

            self.secure_connect(&uri.addr(), creds)
        } else {
            log::warn!(
                logger,
                "Creating insecure gRPC connection to {}",
                uri.addr(),
            );

            self.connect(&uri.addr())
        }
    }
}

/// A trait to ease grpio server construction from URIs.
pub trait ConnectionUriGrpcioServer {
    /// Bind a ServerBuilder using information from a URI.
    fn bind_using_uri(self, uri: &impl ConnectionUri) -> Self;
}

impl ConnectionUriGrpcioServer for ServerBuilder {
    fn bind_using_uri(self, uri: &impl ConnectionUri) -> Self {
        if uri.use_tls() {
            let server_credentials = ServerCredentialsBuilder::new()
                .add_cert(
                    uri.tls_chain()
                        .expect("Uri must have tls-chain when using TLS"),
                    uri.tls_key()
                        .expect("Uri must have tls-key in when using TLS"),
                )
                .build();

            self.bind_with_cred(uri.host(), uri.port(), server_credentials)
        } else {
            self.bind(uri.host(), uri.port())
        }
    }
}
