// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A `grpcio::ServerCredentialsFetcher` implementation that reloads a GRPC's server
//! TLS certificate/key when a SIGHUP is received.

use displaydoc::Display;
use grpcio::{CertificateRequestType, ServerCredentialsBuilder, ServerCredentialsFetcher};
use mc_common::logger::{log, Logger};
use signal_hook::{consts::SIGHUP, flag};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

/// Certificate Reloader error.
#[derive(Debug, Display)]
pub enum ServerCertReloaderError {
    /// IO: {0}
    IO(io::Error),
}

impl From<io::Error> for ServerCertReloaderError {
    fn from(src: io::Error) -> Self {
        Self::IO(src)
    }
}

/// A `grpcio::ServerCredentialsFetcher` implementation that reloads a GRPC's server
/// TLS certificate/key when a SIGHUP is received.
pub struct ServerCertReloader {
    /// Certificate file to watch.
    cert_file: PathBuf,

    /// Private ke yfile to watch.
    key_file: PathBuf,

    /// Signal that we need to re-load the certificate/key files.
    load_needed: Arc<AtomicBool>,

    /// Logger.
    logger: Logger,
}

impl ServerCertReloader {
    /// Create a new ServerCertReloader that watches `cert_file`/`key_file`.
    pub fn new(
        cert_file: &impl AsRef<Path>,
        key_file: &impl AsRef<Path>,
        logger: Logger,
    ) -> Result<Self, ServerCertReloaderError> {
        let load_needed = Arc::new(AtomicBool::new(true));

        flag::register(SIGHUP, load_needed.clone())?;

        Ok(Self {
            cert_file: cert_file.as_ref().to_path_buf(),
            key_file: key_file.as_ref().to_path_buf(),
            load_needed,
            logger,
        })
    }
}

impl ServerCredentialsFetcher for ServerCertReloader {
    fn fetch(&self) -> Result<Option<ServerCredentialsBuilder>, Box<dyn std::error::Error>> {
        if !self.load_needed.load(Ordering::SeqCst) {
            return Ok(None);
        }

        log::info!(self.logger, "Loading certificates");

        let crt = fs::read_to_string(&self.cert_file)?;
        let key = fs::read_to_string(&self.key_file)?;

        let new_cred = ServerCredentialsBuilder::new()
            // This sets the client root certificate to verify client's identity.
            // We are not using this feature, however grpcio still requires something to be set
            // there when using the ServerCredentialsFetcher mechanism. As a workaround we are
            // using the server's certificate chain here.
            .root_cert(
                crt.as_bytes().to_vec(),
                CertificateRequestType::DontRequestClientCertificate,
            )
            .add_cert(crt.into(), key.into());

        self.load_needed.store(false, Ordering::SeqCst);
        Ok(Some(new_cred))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{health_api::PingRequest, health_api_grpc::HealthClient, HealthService};
    use grpcio::{ChannelBuilder, ChannelCredentialsBuilder, EnvBuilder, Server, ServerBuilder};
    use mc_common::logger::test_with_logger;
    use std::{io::Read, thread, time::Duration};

    pub fn read_single_crt(name: &str) -> Result<String, io::Error> {
        let mut crt = String::new();
        fs::File::open(format!("tests/certs/{}.crt", name))?.read_to_string(&mut crt)?;
        Ok(crt)
    }

    fn create_test_server(
        cert_file: &impl AsRef<Path>,
        key_file: &impl AsRef<Path>,
        logger: Logger,
    ) -> (Server, u16) {
        let env = Arc::new(EnvBuilder::new().build());
        let service = HealthService::new(None, logger.clone()).into_service();

        let mut server = ServerBuilder::new(env.clone())
            .register_service(service)
            .bind_with_fetcher(
                "localhost",
                0,
                Box::new(ServerCertReloader::new(&cert_file, &key_file, logger.clone()).unwrap()),
                CertificateRequestType::DontRequestClientCertificate,
            )
            .build()
            .unwrap();
        server.start();
        let port = server.bind_addrs().next().unwrap().1;

        log::info!(logger, "Server started on port {}", port);

        (server, port)
    }

    fn create_test_client(crt_name: &str, ssl_target: &str, port: u16) -> HealthClient {
        let env = Arc::new(EnvBuilder::new().build());
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt(crt_name).unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target(ssl_target)
            .secure_connect(&format!("localhost:{}", port), cred);
        HealthClient::new(ch)
    }

    #[test_with_logger]
    fn test_cert_reloading(logger: Logger) {
        let temp_dir = tempdir::TempDir::new("cert-reload").unwrap();
        let cert_file = temp_dir.path().join("server.crt");
        let key_file = temp_dir.path().join("server.key");

        // Copy server1's cert files into the temp dir.
        std::fs::copy("tests/certs/server1.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server1.key", &key_file).unwrap();

        // Start the GRPC server.
        let (_server, port) = create_test_server(&cert_file, &key_file, logger.clone());

        // Connect the server whose CN is "www.server1.com" with the correct certificate.
        let client1 = create_test_client("server1", "www.server1.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client1.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        // Connect the server whose CN is "www.server1.com" with a different ssl target should fail.
        let client2 = create_test_client("server1", "www.server2.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client2.ping(&req).is_err());

        // Connect the server whose CN is "www.server1.com" with an incorrect certificate.
        let client3 = create_test_client("server2", "www.server1.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client3.ping(&req).is_err());

        // Connecting with server2/"www.server2.com" should not work until we replace the certificate
        // and key file.
        let client4 = create_test_client("server2", "www.server2.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client4.ping(&req).is_err());

        // Replace server1 certificates with server2. This should trigger the reloading mechanism.
        std::fs::copy("tests/certs/server2.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server2.key", &key_file).unwrap();

        // Trigger reloading.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }

        // Give the reloader time to pick up the changes.
        thread::sleep(Duration::from_secs(2));

        // We should be able to connect using "www.server2.com".
        let client5 = create_test_client("server2", "www.server2.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client5.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        // The original client should still be functional.
        req.set_data(vec![5, 6, 7]);
        let reply = client1.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![5, 6, 7]);

        // The previous server2 client should also work.
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client4.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);
    }

    #[test_with_logger]
    fn test_reload_invalid_data(logger: Logger) {
        let temp_dir = tempdir::TempDir::new("cert-reload").unwrap();
        let cert_file = temp_dir.path().join("server.crt");
        let key_file = temp_dir.path().join("server.key");

        // Copy server1's cert files into the temp dir.
        std::fs::copy("tests/certs/server1.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server1.key", &key_file).unwrap();

        // Start the GRPC server.
        let (_server, port) = create_test_server(&cert_file, &key_file, logger.clone());

        // Sanity that the server works.
        let client1 = create_test_client("server1", "www.server1.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client1.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        // Replace the certificate file with junk.
        fs::write(cert_file, "junk").unwrap();

        // Trigger reloading.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }

        // Give the reloader time to pick up the changes.
        thread::sleep(Duration::from_secs(2));

        // Server should still respond with the old certificate.
        let client2 = create_test_client("server1", "www.server1.com", port);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client2.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);
    }

    #[test_with_logger]
    fn test_multiple_servers(logger: Logger) {
        let temp_dir = tempdir::TempDir::new("cert-reload").unwrap();
        let cert_file = temp_dir.path().join("server.crt");
        let key_file = temp_dir.path().join("server.key");

        // Copy server1's cert files into the temp dir.
        std::fs::copy("tests/certs/server1.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server1.key", &key_file).unwrap();

        // Start the GRPC servers.
        let (_server1, port1) = create_test_server(&cert_file, &key_file, logger.clone());
        let (_server2, port2) = create_test_server(&cert_file, &key_file, logger.clone());

        // Sanity that the servers works.
        let client1 = create_test_client("server1", "www.server1.com", port1);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client1.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        let client2 = create_test_client("server1", "www.server1.com", port2);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client2.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        // Replace server1 certificates with server2. This should trigger the reloading mechanism.
        std::fs::copy("tests/certs/server2.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server2.key", &key_file).unwrap();

        // Trigger reloading.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }

        // Give the reloader time to pick up the changes.
        thread::sleep(Duration::from_secs(2));

        // Both servers should now have the new cerficates.
        let client3 = create_test_client("server2", "www.server2.com", port1);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client3.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        let client4 = create_test_client("server2", "www.server2.com", port2);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client4.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);
    }
}
