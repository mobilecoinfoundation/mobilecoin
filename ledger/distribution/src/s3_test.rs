// Copyright (c) 2026 The MobileCoin Foundation

//! S3 protocol regression tests using a local HTTP endpoint and fake
//! credentials.

use super::*;
use httpmock::{HttpMockRequest, HttpMockResponse, MockServer};
use mc_blockchain_types::BlockVersion;
use mc_common::logger::test_with_logger;
use mc_ledger_db::test_utils::{create_ledger, initialize_ledger};
use mc_transaction_core::AccountKey;
use mc_util_test_helper::{RngType, SeedableRng};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{channel, Receiver},
    },
    thread,
    time::Duration,
};

struct Server {
    server: MockServer,
    requests: Receiver<HttpMockRequest>,
}

impl Server {
    fn new(statuses: impl IntoIterator<Item = u16>) -> Self {
        let server = MockServer::start();
        let (sender, requests) = channel();
        let statuses: Vec<_> = statuses.into_iter().collect();
        let next = AtomicUsize::new(0);
        server.mock(|_when, then| {
            then.respond_with(move |request| {
                sender.send(request.clone()).unwrap();
                HttpMockResponse::builder()
                    .status(
                        statuses
                            .get(next.fetch_add(1, Ordering::Relaxed))
                            .copied()
                            .unwrap_or(200),
                    )
                    .build()
            });
        });
        Self { server, requests }
    }

    fn request(&self) -> HttpMockRequest {
        self.requests.recv_timeout(Duration::from_secs(5)).unwrap()
    }

    fn config(&self) -> aws_sdk_s3::config::Builder {
        aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::v2026_01_12())
            .region(Some(Region::new("us-east-1")))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test-access-key",
                "test-secret-key",
                None,
                None,
                "test",
            ))
            .endpoint_url(self.server.base_url())
    }

    fn writer(&self, prefix: &str, logger: Logger) -> S3BlockWriter {
        S3BlockWriter::from_config(
            "test-bucket".into(),
            PathBuf::from(prefix),
            self.config(),
            logger,
        )
    }
}

// A regression must fail the test rather than get stuck in the production
// writer's deliberately unbounded retry loop.
fn with_timeout(test: impl FnOnce() + Send + 'static) {
    let (sender, receiver) = channel();
    let worker = thread::spawn(move || {
        test();
        let _ = sender.send(());
    });
    match receiver.recv_timeout(Duration::from_secs(30)) {
        Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => worker.join().unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("S3 test exceeded 30 seconds"),
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test_with_logger]
fn network_limits_override_inherited_deadlines(logger: Logger) {
    let runtime = runtime();
    let _guard = runtime.enter();
    let server = Server::new([]);
    let inherited = server
        .config()
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(Duration::from_secs(1))
                .read_timeout(Duration::from_secs(2))
                .operation_timeout(Duration::from_secs(3))
                .operation_attempt_timeout(Duration::from_secs(4))
                .build(),
        )
        .stalled_stream_protection(
            StalledStreamProtectionConfig::enabled()
                .upload_enabled(false)
                .download_enabled(false)
                .grace_period(Duration::from_secs(5))
                .build(),
        );
    let writer =
        S3BlockWriter::from_config("test-bucket".into(), "prefix".into(), inherited, logger);
    let config = writer.s3_client.config();
    let timeouts = config.timeout_config().unwrap();
    assert_eq!(timeouts.connect_timeout(), Some(Duration::from_secs(30)));
    assert_eq!(timeouts.read_timeout(), Some(Duration::from_secs(60 * 60)));
    assert_eq!(timeouts.operation_timeout(), None);
    assert_eq!(timeouts.operation_attempt_timeout(), None);
    let protection = config.stalled_stream_protection().unwrap();
    assert!(protection.upload_enabled());
    assert!(protection.download_enabled());
    assert_eq!(protection.grace_period(), Duration::from_secs(120));
}

fn blocks() -> Vec<BlockData> {
    let mut rng = RngType::from_seed([0; 32]);
    let key = AccountKey::random(&mut rng);
    let mut ledger = create_ledger();
    initialize_ledger(BlockVersion::MAX, &mut ledger, 3, &key, &mut rng);
    (0..3)
        .map(|index| ledger.get_block_data(index).unwrap())
        .collect()
}

fn check_signed(request: &HttpMockRequest) {
    let headers = request.headers();
    let authorization = headers["authorization"].to_str().unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=test-access-key/"));
    assert!(authorization.contains("/us-east-1/s3/aws4_request"));
}

#[test_with_logger]
fn uploads_and_head_preserve_archive_layout(logger: Logger) {
    with_timeout(move || {
        let runtime = runtime();
        let _guard = runtime.enter();
        let blocks = blocks();
        for prefix in ["", "node.example/nested"] {
            let server = Server::new([]);
            let mut writer = server.writer(prefix, logger.clone());
            let base = if prefix.is_empty() {
                "/test-bucket".to_owned()
            } else {
                format!("/test-bucket/{prefix}")
            };

            writer.write_single_block(&blocks[1]);
            let single = server.request();
            assert_eq!(single.method_str(), "PUT");
            assert_eq!(
                single.uri().path(),
                format!("{base}/00/00/00/00/00/00/00/0000000000000001.pb")
            );
            assert_eq!(single.headers()["x-amz-acl"], "public-read");
            assert_eq!(single.headers()["x-amz-sdk-checksum-algorithm"], "CRC32");
            assert!(!single.headers()["x-amz-checksum-crc32"].is_empty());
            assert_eq!(
                single.body_ref(),
                blockchain::ArchiveBlock::from(&blocks[1]).encode_to_vec()
            );
            check_signed(&single);

            writer.write_multiple_blocks(&blocks);
            let merged = server.request();
            assert_eq!(merged.method_str(), "PUT");
            assert_eq!(
                merged.uri().path(),
                format!("{base}/merged-3/00/00/00/00/00/00/00/0000000000000000.pb")
            );
            assert_eq!(merged.headers()["x-amz-acl"], "public-read");
            assert_eq!(merged.headers()["x-amz-sdk-checksum-algorithm"], "CRC32");
            assert!(!merged.headers()["x-amz-checksum-crc32"].is_empty());
            assert_eq!(
                merged.body_ref(),
                blockchain::ArchiveBlocks::from(blocks.as_slice()).encode_to_vec()
            );
            check_signed(&merged);

            assert!(writer.block_exists(1));
            let head = server.request();
            assert_eq!(head.method_str(), "HEAD");
            assert_eq!(head.uri().path(), single.uri().path());
            check_signed(&head);
        }
    });
}

#[test_with_logger]
fn missing_blocks_return_false(logger: Logger) {
    with_timeout(move || {
        let runtime = runtime();
        let _guard = runtime.enter();
        let server = Server::new([404]);
        assert!(!server.writer("prefix", logger).block_exists(0));
        assert_eq!(server.request().method_str(), "HEAD");
    });
}

#[test_with_logger]
fn forbidden_head_is_retried(logger: Logger) {
    with_timeout(move || {
        let runtime = runtime();
        let _guard = runtime.enter();
        let server = Server::new([403, 200]);
        assert!(server.writer("prefix", logger).block_exists(0));
        let first = server.request();
        let second = server.request();
        assert_eq!(first.method_str(), "HEAD");
        assert_eq!(first.uri().path(), second.uri().path());
    });
}

#[test_with_logger]
fn transient_upload_failure_is_retried(logger: Logger) {
    with_timeout(move || {
        let runtime = runtime();
        let _guard = runtime.enter();
        let server = Server::new([503, 200]);
        server
            .writer("prefix", logger)
            .write_single_block(&blocks()[1]);
        let first = server.request();
        let second = server.request();
        assert_eq!(first.method_str(), "PUT");
        assert_eq!(first.uri().path(), second.uri().path());
        assert_eq!(first.body_ref(), second.body_ref());
        assert_eq!(
            first.headers()["x-amz-checksum-crc32"],
            second.headers()["x-amz-checksum-crc32"]
        );
        assert_eq!(second.headers()["x-amz-acl"], "public-read");
    });
}

#[test_with_logger]
fn default_credentials_support_environment_and_profiles(logger: Logger) {
    const CHILD_ENV: &str = "MOBILECOIN_TEST_CREDENTIALS";
    if std::env::var_os(CHILD_ENV).is_some() {
        let runtime = runtime();
        let _guard = runtime.enter();
        let writer = S3BlockWriter::new("test-bucket".into(), "prefix".into(), None, logger);
        assert!(writer.block_exists(0));
        return;
    }

    with_timeout(move || {
        for environment in [true, false] {
            let server = Server::new([]);
            let directory = tempfile::TempDir::new().unwrap();
            let config = directory.path().join("config");
            let credentials = directory.path().join("credentials");
            std::fs::write(&config, "[default]\nregion = us-east-1\n").unwrap();
            let profile_key = if environment {
                "shadowed-profile-key"
            } else {
                "test-access-key"
            };
            std::fs::write(&credentials, format!("[default]\naws_access_key_id = {profile_key}\naws_secret_access_key = test-secret-key\naws_session_token = test-session-token\n")).unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "s3_test::default_credentials_support_environment_and_profiles",
                    "--nocapture",
                ])
                .env(CHILD_ENV, "1")
                .env("AWS_CONFIG_FILE", config)
                .env("AWS_SHARED_CREDENTIALS_FILE", credentials)
                .env("AWS_ENDPOINT_URL_S3", server.server.base_url())
                .env("AWS_IGNORE_CONFIGURED_ENDPOINT_URLS", "false")
                .env("AWS_EC2_METADATA_DISABLED", "true")
                .env("AWS_REGION", "us-east-1")
                .env_remove("AWS_DEFAULT_REGION")
                .env_remove("AWS_PROFILE")
                .env_remove("AWS_DEFAULT_PROFILE")
                .env_remove("AWS_ENDPOINT_URL")
                .env_remove("AWS_ACCESS_KEY_ID")
                .env_remove("AWS_SECRET_ACCESS_KEY")
                .env_remove("AWS_SESSION_TOKEN")
                .env_remove("AWS_SECURITY_TOKEN")
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            if environment {
                command
                    .env("AWS_ACCESS_KEY_ID", "test-access-key")
                    .env("AWS_SECRET_ACCESS_KEY", "test-secret-key")
                    .env("AWS_SESSION_TOKEN", "test-session-token");
            }
            let mut child = command.spawn().unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while child.try_wait().unwrap().is_none() {
                if std::time::Instant::now() >= deadline {
                    child.kill().unwrap();
                    let output = child.wait_with_output().unwrap();
                    panic!("credential test timed out: {output:?}");
                }
                thread::sleep(Duration::from_millis(10));
            }
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "credential test failed: {output:?}"
            );
            let request = server.request();
            assert_eq!(request.method_str(), "HEAD");
            assert_eq!(
                request.headers()["x-amz-security-token"],
                "test-session-token"
            );
            check_signed(&request);
        }
    });
}
