// Copyright (c) 2018-2022 The MobileCoin Foundation

use chrono::{offset::Utc, DateTime, Datelike, Duration, Timelike};
use core::{ptr::null_mut, slice::from_raw_parts_mut};
use mbedtls::{
    hash::Type as HashType,
    pk::Pk,
    rng::RngCallback,
    x509::{certificate::Builder, KeyUsage, Time},
};
use mbedtls_sys::types::{
    raw_types::{c_int, c_uchar, c_void},
    size_t,
};
use mc_util_build_script::Environment;
use mc_util_build_sgx::{IasMode, SgxEnvironment, SgxMode};
use p256::{
    ecdsa::SigningKey,
    pkcs8::{EncodePrivateKey, LineEnding},
};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    env,
    fs::write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

lazy_static::lazy_static! {
    static ref RNG: Arc<Mutex<Hc128Rng>> = Arc::new(Mutex::new({
        let mut seed = <Hc128Rng as SeedableRng>::Seed::default();
        match env::var("MC_SEED") {
            Ok(seed_hex) => {
                cargo_emit::warning!(
                    "Using MC_SEED to generate mock attestation report signatories for simulation-mode enclaves"
                );
                hex::decode_to_slice(seed_hex, &mut seed).expect("Error decoding MC_SEED");
            },
            Err(_) => {
                cargo_emit::warning!(
                    "Using thread_rng() to generate mock attestation report signatories for simulation-mode enclaves"
                );
                let mut csprng = rand::thread_rng();
                csprng.fill_bytes(&mut seed[..]);
            }
        }
        Hc128Rng::from_seed(seed)
    }));
}

struct RngForMbedTls;

impl RngCallback for RngForMbedTls {
    #[inline(always)]
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = from_raw_parts_mut(data, len);
        (*RNG)
            .lock()
            .expect("Could not acquire lock on RNG")
            .fill_bytes(outbuf);
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        null_mut()
    }
}

fn main() {
    // This path is inside of the repo and not the normal output directory.
    // This is to reuse the generated files between the main build and the enclave
    // builds. There is not a good way to communicate a common build directory
    // between the different builds.
    let base_dir = env::var("CARGO_MANIFEST_DIR").expect("Could not read manifest dir");
    let data_path = PathBuf::from(base_dir).join("data").join("sim");

    let env = Environment::default();
    let sgx = SgxEnvironment::new(&env).expect("Could not parse SGX environment");

    if sgx.sgx_mode() == SgxMode::Simulation {
        cargo_emit::rustc_cfg!("feature=\"sgx-sim\"");
    }

    if sgx.ias_mode() == IasMode::Development {
        cargo_emit::rustc_cfg!("feature=\"ias-dev\"");
    }

    if should_generating_sim_files(&data_path) {
        generate_sim_files(&data_path);
    }
}

const ROOT_ANCHOR_FILENAME: &str = "root_anchor.pem";
const SIGNER_KEY_FILENAME: &str = "signer.key";
const CHAIN_FILENAME: &str = "chain.pem";

const GENERATED_FILENAMES: &[&str] = &[ROOT_ANCHOR_FILENAME, SIGNER_KEY_FILENAME, CHAIN_FILENAME];

/// An issuer of a certificate. This is the one that signs a certificate.
struct Issuer<'a> {
    /// The key used to sign issued certificates
    key: SigningKey,
    /// A description of the issuer, in the form of a Distinguished Name (DN)
    description: &'a str,
}

/// The subject of a certificate.
struct Subject<'a> {
    /// The serial number of the certificate. Since this is only used in sim
    /// environments we can limit this to 1 byte.
    serial: u8,
    /// The description of the subject, in the form of a Distinguished Name (DN)
    description: &'a str,
    /// Is this a CA certificate?
    is_ca: bool,
    /// The validity times of the certificate
    validity: Validity,
}

/// Validity times
#[derive(Debug, Clone)]
struct Validity {
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

impl Validity {
    /// Returns mbedtls times, `(not_before, not_after)`.
    fn to_mbedtls_times(&self) -> (Time, Time) {
        let not_before = to_mbdetls_time(self.not_before);
        let not_after = to_mbdetls_time(self.not_after);
        (not_before, not_after)
    }
}

fn generate_sim_files(data_path: impl AsRef<Path>) {
    let data_path = data_path.as_ref();

    let root_anchor_path = data_path.join(ROOT_ANCHOR_FILENAME);
    let signer_key_path = data_path.join(SIGNER_KEY_FILENAME);
    let chain_path = data_path.join(CHAIN_FILENAME);

    const ROOT_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signing CA\0";
    const SIGNER_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signer\0";

    let now = Utc::now();
    let not_before = now - Duration::hours(1);
    let not_after = not_before + Duration::days(30);
    let validity = Validity {
        not_before,
        not_after,
    };

    let subject = Subject {
        serial: 1,
        description: ROOT_SUBJECT,
        is_ca: true,
        validity: validity.clone(),
    };
    let (root_cert_pem, root_key) = create_certificate(None, &subject);
    write(root_anchor_path, &root_cert_pem).expect("Unable to write root anchor");

    let issuer = Issuer {
        key: root_key,
        description: ROOT_SUBJECT,
    };
    let subject = Subject {
        serial: 2,
        description: SIGNER_SUBJECT,
        is_ca: false,
        validity,
    };
    let (signer_cert_pem, signer_key) = create_certificate(issuer, &subject);
    write(chain_path, signer_cert_pem + &root_cert_pem).expect("Unable to write cert chain");

    write_signing_key(signer_key_path, &signer_key);
}

/// Returns true of the build script should generate the sim files
fn should_generating_sim_files(data_path: impl AsRef<Path>) -> bool {
    let data_path = data_path.as_ref();
    cargo_emit::rerun_if_env_changed!("MC_SEED");

    let generated_files = GENERATED_FILENAMES
        .iter()
        .map(|file| data_path.join(file))
        .collect::<Vec<_>>();
    for file in generated_files.iter() {
        cargo_emit::rerun_if_changed!(file.to_str().expect("Could not stringify path"));
    }

    let regenerate_time = SystemTime::now()
        - Duration::weeks(1)
            .to_std()
            .expect("Failed to convert to std duration");

    if generated_files.iter().any(|file| {
        file.metadata()
            .and_then(|f| f.modified().map(|t| t < regenerate_time))
            .unwrap_or(true)
    }) {
        return true;
    }

    // If we got this far we assume that the MC_SEED environment variable was
    // changed. The downside to this approach is that if the MC_SEED is set
    // initially there will always be one incremental build:
    // - first build the generated files are created, which tells cargo to re-run
    //   this build script
    // - The second build will get down to here, see the MC_SEED env variable is set
    //   and regenerate the files.
    // - The third build cargo should skip this build script.
    env::var("MC_SEED").is_ok()
}

/// Create a certificate
///
/// # Aruments:
/// * `issuer` - The issuer of the certificate. If `None` then the certificate
///   is self signed.
/// * `subject` - The subject of the certificate
///
/// # Returns:
/// The PEM encoded certificate and the signing key of the certificate
fn create_certificate<'a>(
    issuer: impl Into<Option<Issuer<'a>>>,
    subject: &Subject,
) -> (String, SigningKey) {
    let subject_signing_key = SigningKey::random(&mut *RNG.lock().expect("mutex poisoned"));

    // No issuer means it's self signed
    let issuer = issuer.into().unwrap_or_else(|| Issuer {
        key: subject_signing_key.clone(),
        description: subject.description,
    });

    let mut issuer_key = to_mbedtls_key_context(&issuer.key);
    let mut subject_key = to_mbedtls_key_context(&subject_signing_key);
    let (not_before, not_after) = subject.validity.to_mbedtls_times();

    let key_usage = if subject.is_ca {
        KeyUsage::CRL_SIGN | KeyUsage::KEY_CERT_SIGN
    } else {
        KeyUsage::DIGITAL_SIGNATURE | KeyUsage::NON_REPUDIATION
    };

    let mut csprng = RngForMbedTls {};
    let mut builder = Builder::new();
    builder
        .subject_with_nul(subject.description)
        .expect("Could not set subject")
        .issuer_with_nul(issuer.description)
        .expect("Could not set issuer")
        .basic_constraints(subject.is_ca, Some(0))
        .expect("Could not set basic constraints")
        .key_usage(key_usage)
        .expect("Could not set key usage")
        .validity(not_before, not_after)
        .expect("Could not set time validity range")
        .serial(&[subject.serial])
        .expect("Could not set serial number")
        .subject_key(&mut subject_key)
        .issuer_key(&mut issuer_key)
        .signature_hash(HashType::Sha256);
    let cert_pem = builder
        .write_pem_string(&mut csprng)
        .expect("Could not create PEM string of certificate");
    (cert_pem, subject_signing_key)
}

/// Convert the provided `key` into an mbedtls key context.
///
/// The mbedtls key context contains both the public and private keys.
fn to_mbedtls_key_context(key: &SigningKey) -> Pk {
    let der_key = key
        .to_pkcs8_der()
        .expect("Could not export private key to DER");
    let key_context = Pk::from_private_key(der_key.as_bytes(), None)
        .expect("Could not parse private key from DER");
    key_context
}

fn to_mbdetls_time(time: DateTime<Utc>) -> Time {
    Time::new(
        u16::try_from(time.year()).expect("Year not a u16"),
        u8::try_from(time.month()).expect("Month not a u8"),
        u8::try_from(time.day()).expect("Day not a u8"),
        u8::try_from(time.hour()).expect("Hour not a u8"),
        u8::try_from(time.minute()).expect("Minute not a u8"),
        u8::try_from(time.second()).expect("Second not a u8"),
    )
    .expect("Could not create a valid mbedtls time")
}

fn write_signing_key(signer_key_path: impl AsRef<Path>, signer_key: &SigningKey) {
    let signer_key_path = signer_key_path.as_ref();
    let der_signer_key = signer_key
        .to_pkcs8_der()
        .expect("Could not export privkey to DER");
    write(
        signer_key_path,
        der_signer_key
            .to_pem("PRIVATE KEY", LineEnding::LF)
            .expect("Could not encode signer key to PEM"),
    )
    .expect("Could not write signer key PEM to file");
}
