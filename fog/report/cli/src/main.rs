// Copyright (c) 2018-2021 The MobileCoin Foundation

//! A CLI tool that resolves FogPubkey requests
//!
//! This is used so that python can get the fog pubkey bytes as a hex string,
//! and then use them in the fog conformance test to create fog TxOuts.
//!
//! At time of writing, it takes the public address of a user (.pub keyfile),
//! since the FogPubkeyResolver API fully validates the fog report and the
//! user's signature over the cert chain.
//! In the future if needed we could make this take only the fog report url
//! and report id, and not fully validate the pubkey, but that would require
//! code changes in the GrpcFogPubkeyResolver object. It might make this a more
//! useful diagnostic tool.

use binascii::bin2hex;
use grpcio::EnvBuilder;
use mc_account_keys::{AccountKey, PublicAddress};
use mc_attest_core::{Verifier, DEBUG_ENCLAVE};
use mc_common::logger::{create_root_logger, log, Logger};
use mc_crypto_keys::{CompressedRistrettoPublic, RistrettoPublic};
use mc_fog_api::report_parse::try_extract_unvalidated_ingress_pubkey_from_fog_report;
use mc_fog_report_connection::{Error, GrpcFogReportConnection};
use mc_fog_report_validation::{
    FogPubkeyResolver, FogReportResponses, FogResolver, FullyValidatedFogPubkey,
};
use mc_util_uri::FogUri;
use std::{
    convert::TryFrom,
    path::PathBuf,
    process::exit,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use structopt::StructOpt;

/// A command line utility to reach out to the fog report server and fetch the
/// ingest report, and optionally validate it.
///
/// This command prints the bytes of the ingress pubkey in hex, with no newline,
/// so that it can be easily captured by automation.
/// Optionally, it also shows the pubkey-expiry value, in this case the output
/// is json formatted.
///
/// The action can be specified in a few ways:
/// - Supply a path to a public address file. This will perform full validation,
///   as if we were sending to this fog user.
/// - Supply a fog-url and a fog-spki. This will perform full validation, that
///   would be performed for a fog user with these values in their address.
/// - Supply only a fog-url. This can only be used with the "no-validate"
///   option.
#[derive(Debug, StructOpt)]
struct Config {
    /// Path to mobilecoin public address. Fog url and spki will be extracted,
    /// and fog signature will be checked, unless no-validate is passed.
    #[structopt(long = "public-address", short = "p")]
    pub public_address: Option<PathBuf>,

    /// The fog url to hit.
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-url", short = "u")]
    pub fog_url: Option<String>,

    /// The fog report id to find.
    /// This is optional and almost always defaulted to "".
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-report-id", short = "i")]
    pub fog_report_id: Option<String>,

    /// The fog authority spki, in base 64
    /// If omitted, then NO verification of any kind (IAS, MRSIGNER, cert
    /// chains) will be performed.
    /// If a public address is supplied, this cannot be supplied.
    #[structopt(long = "fog-spki", short = "s")]
    pub fog_spki: Option<String>,

    /// How long to retry if NoReports, this is useful for tests
    #[structopt(long = "retry-seconds", short = "r", default_value = "10")]
    pub retry_seconds: u64,

    /// Outputs json containing the hex bytes of fog ingress pubkey,
    /// and the pubkey expiry value
    #[structopt(long = "show-expiry", short = "v")]
    pub show_expiry: bool,

    /// Skip all validation of the fog response, including IAS, cert checking,
    /// and fog authority signature.
    #[structopt(long = "no-validate", short = "n")]
    pub no_validate: bool,
}

/// Get fog response with retries, retrying if NoReports error occurs
fn get_fog_response_with_retries(
    fog_uri: FogUri,
    retry_duration: Duration,
    logger: &Logger,
) -> FogReportResponses {
    // Create the grpc object and report verifier
    let grpc_env = Arc::new(EnvBuilder::new().name_prefix("cli").build());

    let conn = GrpcFogReportConnection::new(grpc_env, logger.clone());

    let deadline = Instant::now() + retry_duration;
    loop {
        match conn.fetch_fog_reports(core::slice::from_ref(&fog_uri).iter().cloned()) {
            Ok(result) => {
                return result;
            }
            Err(Error::NoReports(_)) => {
                std::thread::sleep(Duration::from_millis(500));
                if Instant::now() > deadline {
                    eprintln!("No reports after {:?} time retrying", retry_duration);
                    exit(1)
                }
            }
            Err(err) => {
                eprintln!("Could not get fog response ({}): {}", fog_uri, err);
                exit(1);
            }
        }
    }
}

/// Try to resolve a public address to a fog public key
fn get_validated_pubkey(
    responses: FogReportResponses,
    pub_addr: PublicAddress,
    logger: &Logger,
) -> FullyValidatedFogPubkey {
    let mut verifier = Verifier::default();

    {
        let mr_signer_verifier = mc_fog_ingest_enclave_measurement::get_mr_signer_verifier(None);
        verifier.debug(DEBUG_ENCLAVE).mr_signer(mr_signer_verifier);
    }

    log::debug!(logger, "IAS verifier: {:?}", &verifier);

    let resolver = FogResolver::new(responses, &verifier);
    resolver
        .expect("Could not get FogPubkey resolved")
        .get_fog_pubkey(&pub_addr)
        .expect("Could not validate fog pubkey")
}

/// Try to grab pubkey and expiry out of the response without validating
fn get_unvalidated_pubkey(
    responses: FogReportResponses,
    fog_uri: FogUri,
    fog_report_id: String,
    _logger: &Logger,
) -> (RistrettoPublic, u64) {
    let resp = responses
        .get(&fog_uri.to_string())
        .expect("Didn't find response from this URI");
    let rep = resp
        .reports
        .iter()
        .find(|rep| rep.fog_report_id == fog_report_id)
        .expect("Didn't find report with the right report id");
    let pubkey_expiry = rep.pubkey_expiry;
    // This parses the fog report and extracts the ingress key
    let ingress_pubkey = try_extract_unvalidated_ingress_pubkey_from_fog_report(&rep.report)
        .expect("Could not parse report");
    let pubkey =
        RistrettoPublic::try_from(&ingress_pubkey).expect("report didn't contain a valid key");
    (pubkey, pubkey_expiry)
}

fn main() {
    // Logging must go to stderr to not interfere with STDOUT
    std::env::set_var("MC_LOG_STDERR", "1");
    let config = Config::from_args();
    let logger = create_root_logger();

    // Get public address either from a file, or synthesize from BOTH fog-url and
    // spki. If we only have fog-url, we can't make a public address and we
    // won't do any validation.
    let pub_addr: Option<PublicAddress> = if let Some(ref path) = config.public_address {
        let pub_addr =
            mc_util_keyfile::read_pubfile(path).expect("Could not read public address file");
        if config.fog_url.is_some() {
            panic!("Can't specify public address file and fog url");
        }
        if config.fog_report_id.is_some() {
            panic!("Can't specify public address file and fog report id");
        }
        if config.fog_spki.is_some() {
            panic!("Can't specify public address file and fog spki");
        }
        Some(pub_addr)
    } else if let Some(ref spki) = config.fog_spki {
        log::debug!(logger, "Creating synthetic public address");
        let fog_report_url =
            FogUri::from_str(&config.fog_url.clone().expect("no fog url was specified"))
                .expect("Could not parse fog report url as a valid fog url");

        let report_id = config.fog_report_id.clone().unwrap_or_default();

        let spki = base64::decode(spki).expect("Couldn't decode spki as base 64");

        let account_key = AccountKey::new_with_fog(
            &Default::default(),
            &Default::default(),
            fog_report_url,
            report_id,
            spki,
        );
        Some(account_key.default_subaddress())
    } else {
        None
    };

    // Get pubkey and pubkey expiry, using either validated or unvalidated path
    let (pubkey, pubkey_expiry): (RistrettoPublic, u64) = if config.no_validate {
        let fog_uri_str: String = pub_addr
            .map(|addr| {
                addr.fog_report_url()
                    .expect("Fog url is missing")
                    .to_string()
            })
            .unwrap_or_else(|| {
                config
                    .fog_url
                    .as_ref()
                    .expect("Either public address or fog url must be supplied")
                    .to_string()
            });
        let fog_uri = FogUri::from_str(&fog_uri_str)
            .expect("Could not parse fog report url as a valid fog url");

        // Try to make request
        let responses = get_fog_response_with_retries(
            fog_uri.clone(),
            Duration::from_secs(config.retry_seconds),
            &logger,
        );

        // Try to parse the response
        get_unvalidated_pubkey(
            responses,
            fog_uri,
            config.fog_report_id.unwrap_or_default(),
            &logger,
        )
    } else {
        // Use the validated code path. Requires that we are given (or constructed) a
        // public address.
        let pub_addr = pub_addr.expect("Not enough info to validate, either supply full address or spki, or pass --no-validate");

        // Get fog url
        let fog_uri = FogUri::from_str(
            pub_addr
                .fog_report_url()
                .expect("public address had no fog url"),
        )
        .expect("Could not parse fog report url as a valid fog url");

        // Try to make request
        let responses = get_fog_response_with_retries(
            fog_uri,
            Duration::from_secs(config.retry_seconds),
            &logger,
        );

        // Try to validate response
        let result = get_validated_pubkey(responses, pub_addr, &logger);
        (result.pubkey, result.pubkey_expiry)
    };

    let mut hex_buf = [0u8; 64];
    bin2hex(
        CompressedRistrettoPublic::from(&pubkey).as_ref(),
        &mut hex_buf[..],
    )
    .expect("Failed converting to hex");
    let hex_str = std::str::from_utf8(&hex_buf).unwrap();

    // if show-expiry is selected, we show key and expiry, formatted as json
    // else just print the hex bytes of key
    if config.show_expiry {
        print!(
            "{{ \"pubkey\": \"{}\", \"pubkey_expiry\": {} }}",
            hex_str, pubkey_expiry
        );
    } else {
        print!("{}", hex_str);
    }
}
