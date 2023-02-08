// Copyright (c) 2018-2022 The MobileCoin Foundation

//! Extension traits that make it easier to start GRPC servers and connect to
//! them using URIs.

use crate::ServerCertReloader;
use grpcio::{
    CertificateRequestType, Channel, ChannelBuilder, ChannelCredentialsBuilder, Environment,
    Result, Server, ServerBuilder, ServerCredentials,
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
            .keepalive_time(Duration::from_secs(10))
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

            log::debug!(logger, "Creating secure gRPC connection to {}", uri.addr());

            self = self.set_credentials(creds);
            self.connect(&uri.addr())
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
    /// Build a Server from a ServerBuilder using information from a URI and
    /// enable support for hot-reloading certificates when TLS is used.
    fn build_using_uri(self, uri: &impl ConnectionUri, logger: Logger) -> Result<Server>;

    /// Create the default channel settings for server
    fn default_channel_builder(env: Arc<Environment>) -> ChannelBuilder {
        ChannelBuilder::new(env)
            .keepalive_permit_without_calls(true)
            .keepalive_time(Duration::from_secs(10))
            .keepalive_timeout(Duration::from_secs(20))
            .http2_min_recv_ping_interval_without_data(Duration::from_secs(5))
    }

    /// Set the channel args to our defaults.
    #[must_use]
    fn set_default_channel_args(self, env: Arc<Environment>) -> Self;

    /// Get ServerCredentials from a URI
    fn server_credentials_from_uri(uri: &impl ConnectionUri, logger: &Logger) -> ServerCredentials {
        if uri.use_tls() {
            let tls_chain_path = uri
                .tls_chain_path()
                .expect("Uri must have tls-chain when using TLS");
            let tls_key_path = uri
                .tls_key_path()
                .expect("Uri must have tls-key in when using TLS");

            let reloader = ServerCertReloader::new(&tls_chain_path, &tls_key_path, logger.clone())
                .expect("Failed creating ServerCertReloader");

            ServerCredentials::with_fetcher(
                Box::new(reloader),
                CertificateRequestType::DontRequestClientCertificate,
            )
        } else {
            ServerCredentials::insecure()
        }
    }
}

impl ConnectionUriGrpcioServer for ServerBuilder {
    fn build_using_uri(self, uri: &impl ConnectionUri, logger: Logger) -> Result<Server> {
        let server_creds = Self::server_credentials_from_uri(uri, &logger);

        if uri.use_tls() {
            log::debug!(
                logger,
                "Binding secure gRPC server to {}:{}",
                uri.host(),
                uri.port(),
            );
        } else {
            log::warn!(
                logger,
                "Binding insecure gRPC server to {}:{}",
                uri.host(),
                uri.port(),
            );
        }

        let mut server = self.build()?;
        server.add_listening_port(uri.addr(), server_creds)?;
        Ok(server)
    }

    /// Set the channel args to our defaults.
    fn set_default_channel_args(self, env: Arc<Environment>) -> Self {
        self.channel_args(Self::default_channel_builder(env).build_args())
    }
}
