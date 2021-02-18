// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A `grpcio::ServerCredentialsFetcher` implementation that watches the local file system for
//! certificate/key file changes.

use displaydoc::Display;
use grpcio::{CertificateRequestType, ServerCredentialsBuilder, ServerCredentialsFetcher};
use mc_common::logger::{log, Logger};
use notify::{
    watcher, DebouncedEvent, Error as NotifyError, RecommendedWatcher, RecursiveMode, Watcher,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{channel, Receiver},
        Arc,
    },
    thread,
    time::Duration,
};

/// Delay time between checks for the watcher thread stop trigger.
pub const STOP_TRIGGER_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Debounce time for notification events.
pub const NOTIFY_DEBOUNCE: Duration = Duration::from_secs(1);

/// Certificate Reloader error.
#[derive(Debug, Display)]
pub enum ServerCertReloaderError {
    /// Notify: {0}
    Notify(NotifyError),

    /// IO: {0}
    IO(io::Error),
}

impl From<NotifyError> for ServerCertReloaderError {
    fn from(src: NotifyError) -> Self {
        Self::Notify(src)
    }
}

impl From<io::Error> for ServerCertReloaderError {
    fn from(src: io::Error) -> Self {
        Self::IO(src)
    }
}

/// A `grpcio::ServerCredentialsFetcher` implementation that watches the local file system for
/// certificate/key file changes.
pub struct ServerCertReloader {
    /// Certificate file to watch.
    cert_file: PathBuf,

    /// Private ke yfile to watch.
    key_file: PathBuf,

    /// Stop trigger for signalling the worker thread to terminate.
    stop_trigger: Arc<AtomicBool>,

    /// Signal that we need to re-load the certificate/key files.
    load_needed: Arc<AtomicBool>,

    /// Watcher - we need to hold it so that it doesn't stop.
    _watcher: RecommendedWatcher,

    /// Logger.
    logger: Logger,

    /// Join handle for waiting for the worker thread.
    join_handle: Option<thread::JoinHandle<()>>,
}

impl ServerCertReloader {
    /// Create a new ServerCertReloader that watches `cert_file`/`key_file`.
    pub fn new(
        cert_file: &impl AsRef<Path>,
        key_file: &impl AsRef<Path>,
        logger: Logger,
    ) -> Result<Self, ServerCertReloaderError> {
        let (tx, rx) = channel();
        let mut watcher = watcher(tx, NOTIFY_DEBOUNCE)?;

        watcher.watch(cert_file, RecursiveMode::NonRecursive)?;
        watcher.watch(key_file, RecursiveMode::NonRecursive)?;

        let stop_trigger = Arc::new(AtomicBool::new(false));
        let load_needed = Arc::new(AtomicBool::new(true));
        let thread_logger = logger.clone();

        let thread_stop_trigger = stop_trigger.clone();
        let thread_load_needed = load_needed.clone();
        let join_handle = Some(
            thread::Builder::new()
                .name("ServerCertReloader".into())
                .spawn(move || {
                    cert_reloader_thread(rx, thread_stop_trigger, thread_load_needed, thread_logger)
                })?,
        );

        Ok(Self {
            cert_file: cert_file.as_ref().to_path_buf(),
            key_file: key_file.as_ref().to_path_buf(),
            stop_trigger,
            load_needed,
            _watcher: watcher,
            logger,
            join_handle,
        })
    }
}

impl Drop for ServerCertReloader {
    fn drop(&mut self) {
        if let Some(join_handle) = self.join_handle.take() {
            self.stop_trigger.store(true, Ordering::SeqCst);
            let _ = join_handle.join();
        }
    }
}

/// The certificate reloader watcher thread.
/// While watching happens through the `notify` crate, the interface it provides for receiving
/// watcher notifications is an `mpsc::Receiver` which is not Sync. We need ServerCertReloader to
/// be Send+Sync for it to be usable in grpcio's `bind_with_fetcher`. As such, we workaround it
/// with a thread that waits on the queue and changes an atomic variable when a reload is
/// necessary.
fn cert_reloader_thread(
    rx: Receiver<DebouncedEvent>,
    stop_trigger: Arc<AtomicBool>,
    load_needed: Arc<AtomicBool>,
    logger: Logger,
) {
    log::info!(logger, "ServerCertReloader thread started");

    loop {
        if stop_trigger.load(Ordering::SeqCst) {
            log::info!(logger, "ServerCertReloader thread received stop trigger");
            break;
        }

        match rx.recv_timeout(STOP_TRIGGER_POLL_INTERVAL) {
            Ok(DebouncedEvent::Write(event)) => {
                log::info!(
                    logger,
                    "ServerCertReloader got a write event on {:?}",
                    event
                );
                load_needed.store(true, Ordering::SeqCst);
            }
            Ok(_) => {}
            Err(_) => {}
        }
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
    use grpcio::{ChannelBuilder, ChannelCredentialsBuilder, EnvBuilder, ServerBuilder};
    use mc_common::logger::test_with_logger;
    use std::io::Read;

    pub fn read_single_crt(name: &str) -> Result<String, io::Error> {
        let mut crt = String::new();
        fs::File::open(format!("tests/certs/{}.crt", name))?.read_to_string(&mut crt)?;
        Ok(crt)
    }

    #[test_with_logger]
    fn test_cert_reloading(logger: Logger) {
        let env = Arc::new(EnvBuilder::new().build());
        let service = HealthService::new(None, logger.clone()).into_service();

        let temp_dir = tempdir::TempDir::new("cert-reload").unwrap();
        let cert_file = temp_dir.path().join("server.crt");
        let key_file = temp_dir.path().join("server.key");

        // Copy server1's cert files into the temp dir.
        std::fs::copy("tests/certs/server1.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server1.key", &key_file).unwrap();

        // Start the GRPC server.
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

        // Connect the server whose CN is "www.server1.com" with the correct certificate.
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt("server1").unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target("www.server1.com")
            .secure_connect(&format!("localhost:{}", port.clone()), cred);
        let client1 = HealthClient::new(ch);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        let reply = client1.ping(&req).expect("rpc");
        assert_eq!(reply.get_data(), vec![1, 2, 3]);

        // Connect the server whose CN is "www.server1.com" with a different ssl target should fail.
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt("server1").unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target("www.server2.com")
            .secure_connect(&format!("localhost:{}", port.clone()), cred);
        let client2 = HealthClient::new(ch);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client2.ping(&req).is_err());

        // Connect the server whose CN is "www.server1.com" with an incorrect certificate.
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt("server2").unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target("www.server1.com")
            .secure_connect(&format!("localhost:{}", port.clone()), cred);
        let client3 = HealthClient::new(ch);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client3.ping(&req).is_err());

        // Connecting with server2/"www.server2.com" should not work until we replace the certificate
        // and key file.
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt("server2").unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target("www.server2.com")
            .secure_connect(&format!("localhost:{}", port.clone()), cred);
        let client4 = HealthClient::new(ch);
        let mut req = PingRequest::default();
        req.set_data(vec![1, 2, 3]);
        assert!(client4.ping(&req).is_err());

        // Replace server1 certificates with server2. This should trigger the reloading mechanism.
        std::fs::copy("tests/certs/server2.crt", &cert_file).unwrap();
        std::fs::copy("tests/certs/server2.key", &key_file).unwrap();

        // Give the reloader time to pick up the changes.
        thread::sleep(NOTIFY_DEBOUNCE * 2);

        // We should be able to connect using "www.server2.com".
        let cred = ChannelCredentialsBuilder::new()
            .root_cert(read_single_crt("server2").unwrap().into())
            .build();
        let ch = ChannelBuilder::new(env.clone())
            .override_ssl_target("www.server2.com")
            .secure_connect(&format!("localhost:{}", port.clone()), cred);
        let client5 = HealthClient::new(ch);
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
}
