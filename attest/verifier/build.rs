// Copyright (c) 2018-2022 The MobileCoin Foundation

use chrono::{offset::Utc, Datelike, Duration, Timelike};
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

fn generate_sim_files(data_path: impl AsRef<Path>) {
    let data_path = data_path.as_ref();

    let root_anchor_path = data_path.join(ROOT_ANCHOR_FILENAME);
    let signer_key_path = data_path.join(SIGNER_KEY_FILENAME);
    let chain_path = data_path.join(CHAIN_FILENAME);

    const ROOT_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signing CA\0";
    const SIGNER_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signer\0";

    let mut serial: [u8; 1] = [1u8];

    let now = Utc::now();
    let start_time = now - Duration::hours(1);
    let end_time = now + Duration::days(30);

    let mut csprng = RngForMbedTls {};

    // ROOT CERTIFICATE
    let private_key = SigningKey::random(&mut *RNG.lock().expect("mutex poisoned"));
    let der_private_key = private_key
        .to_pkcs8_der()
        .expect("Could not export privkey to DER");
    let mut root_subject_key = Pk::from_private_key(der_private_key.as_bytes(), None)
        .expect("Could not parse privkey from DER");
    let mut root_issuer_key = Pk::from_private_key(der_private_key.as_bytes(), None)
        .expect("Could not parse privkey from DER");
    // Intermediate authority will be signed by this key.
    let mut signer_issuer_key = Pk::from_private_key(der_private_key.as_bytes(), None)
        .expect("Could not parse privkey from DER");

    let root_not_before = Time::new(
        u16::try_from(start_time.year()).expect("Year not a u16"),
        u8::try_from(start_time.month()).expect("Month not a u8"),
        u8::try_from(start_time.day()).expect("Day not a u8"),
        u8::try_from(start_time.hour()).expect("Hour not a u8"),
        u8::try_from(start_time.minute()).expect("Minute not a u8"),
        u8::try_from(start_time.second()).expect("Second not a u8"),
    )
    .expect("Could not create a not_before time");
    let root_not_after = Time::new(
        u16::try_from(end_time.year()).expect("Year not a u16"),
        u8::try_from(end_time.month()).expect("Month not a u8"),
        u8::try_from(end_time.day()).expect("Day not a u8"),
        u8::try_from(end_time.hour()).expect("Hour not a u8"),
        u8::try_from(end_time.minute()).expect("Minute not a u8"),
        u8::try_from(end_time.second()).expect("Second not a u8"),
    )
    .expect("Could not create a not_after time");

    let mut root_builder = Builder::new();
    let root_cert_pem = root_builder
        .subject_with_nul(ROOT_SUBJECT)
        .expect("Could not set subject")
        .issuer_with_nul(ROOT_SUBJECT)
        .expect("Could not set issuer")
        .basic_constraints(true, Some(0))
        .expect("Could not set basic constraints")
        .key_usage(KeyUsage::CRL_SIGN | KeyUsage::KEY_CERT_SIGN)
        .expect("Could not set key usage")
        .validity(root_not_before, root_not_after)
        .expect("Could not set time validity range")
        .serial(&serial[..])
        .expect("Could not set serial number")
        .subject_key(&mut root_subject_key)
        .issuer_key(&mut root_issuer_key)
        .signature_hash(HashType::Sha256)
        .write_pem_string(&mut csprng)
        .expect("Could not create PEM string of certificate");
    write(root_anchor_path, &root_cert_pem).expect("Unable to write root anchor");

    // IAS SIGNER CERT
    let signer_key = SigningKey::random(&mut *RNG.lock().expect("mutex poisoned"));
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

    let mut signer_subject_key = Pk::from_private_key(der_signer_key.as_bytes(), None)
        .expect("Could not parse privkey from DER");

    let signer_not_before = Time::new(
        u16::try_from(start_time.year()).expect("Year not a u16"),
        u8::try_from(start_time.month()).expect("Month not a u8"),
        u8::try_from(start_time.day()).expect("Day not a u8"),
        u8::try_from(start_time.hour()).expect("Hour not a u8"),
        u8::try_from(start_time.minute()).expect("Minute not a u8"),
        u8::try_from(start_time.second()).expect("Second not a u8"),
    )
    .expect("Could not create a not_before time");
    let signer_not_after = Time::new(
        u16::try_from(end_time.year()).expect("Year not a u16"),
        u8::try_from(end_time.month()).expect("Month not a u8"),
        u8::try_from(end_time.day()).expect("Day not a u8"),
        u8::try_from(end_time.hour()).expect("Hour not a u8"),
        u8::try_from(end_time.minute()).expect("Minute not a u8"),
        u8::try_from(end_time.second()).expect("Second not a u8"),
    )
    .expect("Could not create a not_after time");

    serial[0] += 1;

    let mut builder = Builder::new();
    let signer_cert_pem = builder
        .subject_with_nul(SIGNER_SUBJECT)
        .expect("Could not set subject")
        .issuer_with_nul(ROOT_SUBJECT)
        .expect("Could not set issuer")
        .basic_constraints(false, None)
        .expect("Could not set basic constraints")
        .key_usage(KeyUsage::DIGITAL_SIGNATURE | KeyUsage::NON_REPUDIATION)
        .expect("Could not set key usage")
        .validity(signer_not_before, signer_not_after)
        .expect("Could not set time validity range")
        .serial(&serial[..])
        .expect("Could not set serial number")
        .subject_key(&mut signer_subject_key)
        .issuer_key(&mut signer_issuer_key)
        .signature_hash(HashType::Sha256)
        .write_pem_string(&mut csprng)
        .expect("Could not create PEM string of certificate");

    write(chain_path, root_cert_pem + &signer_cert_pem).expect("Unable to write cert chain");
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
