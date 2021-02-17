use grpcio::{
    CertificateRequestType, ChannelBuilder, ChannelCredentialsBuilder, EnvBuilder, ServerBuilder,
    ServerCredentialsBuilder, ServerCredentialsFetcher,
};
use mc_common::logger::{log, test_with_logger, Logger};
use mc_util_grpc::{health_api::PingRequest, health_api_grpc::HealthClient, HealthService};
use std::{fs, io, io::Read, sync::Arc};

struct DataReload {}

pub fn read_single_crt(name: &str) -> Result<String, io::Error> {
    let mut crt = String::new();
    fs::File::open(format!("tests/certs/{}.crt", name))?.read_to_string(&mut crt)?;
    Ok(crt)
}

pub fn read_cert_pair(name: &str) -> Result<(String, String), io::Error> {
    let mut crt = String::new();
    let mut key = String::new();
    fs::File::open(format!("tests/certs/{}.crt", name))?.read_to_string(&mut crt)?;
    fs::File::open(format!("tests/certs/{}.key", name))?.read_to_string(&mut key)?;
    Ok((crt, key))
}

impl ServerCredentialsFetcher for DataReload {
    fn fetch(&self) -> Result<Option<ServerCredentialsBuilder>, Box<dyn std::error::Error>> {
        let (crt, key) = read_cert_pair("server1")?;
        let new_cred = ServerCredentialsBuilder::new()
            .root_cert(
                crt.as_bytes().to_vec(),
                CertificateRequestType::DontRequestClientCertificate,
            )
            .add_cert(crt.into(), key.into());
        Ok(Some(new_cred))
    }
}

#[test_with_logger]
fn test_cert_reloading(logger: Logger) {
    let env = Arc::new(EnvBuilder::new().build());
    let service = HealthService::new(None, logger.clone()).into_service();

    let mut server = ServerBuilder::new(env.clone())
        .register_service(service)
        .bind_with_fetcher(
            "localhost",
            0,
            Box::new(DataReload {}),
            CertificateRequestType::DontRequestClientCertificate,
        )
        .build()
        .unwrap();
    server.start();
    let port = server.bind_addrs().next().unwrap().1;

    log::info!(logger, "Server started on port {}", port);

    // To connect the server whose CN is "www.server1.com".
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
}
