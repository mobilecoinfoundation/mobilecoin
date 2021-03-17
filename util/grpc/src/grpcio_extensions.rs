// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Extension traits that make it easier to start GRPC servers and connect to
//! them using URIs.

use crate::ServerCertReloader;
use grpcio::{
    CertificateRequestType, Channel, ChannelBuilder, ChannelCredentialsBuilder, Environment,
    ServerBuilder,
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
    /// Bind a ServerBuilder using information from a URI and enable support for
    /// hot-reloading certificates when TLS is used.
    fn bind_using_uri(self, uri: &impl ConnectionUri, logger: Logger) -> Self;
}

impl ConnectionUriGrpcioServer for ServerBuilder {
    fn bind_using_uri(self, uri: &impl ConnectionUri, logger: Logger) -> Self {
        if uri.use_tls() {
            let tls_chain_path = uri
                .tls_chain_path()
                .expect("Uri must have tls-chain when using TLS");
            let tls_key_path = uri
                .tls_key_path()
                .expect("Uri must have tls-key in when using TLS");

            let reloader = ServerCertReloader::new(&tls_chain_path, &tls_key_path, logger)
                .expect("Failed creating ServerCertReloader");

            self.bind_with_fetcher(
                uri.host(),
                uri.port(),
                Box::new(reloader),
                CertificateRequestType::DontRequestClientCertificate,
            )
        } else {
            self.bind(uri.host(), uri.port())
        }
    }
}
