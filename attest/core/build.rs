// Copyright (c) 2018-2021 The MobileCoin Foundation

use chrono::{
    offset::{TimeZone, Utc},
    Datelike, Duration, Timelike,
};
use core::{ptr::null_mut, slice::from_raw_parts_mut};
use mbedtls::{
    hash::Type as HashType,
    pk::Pk,
    rng::RngCallback,
    x509::{
        certificate::{Builder, Certificate},
        KeyUsage, Time,
    },
};
use mbedtls_sys::types::{
    raw_types::{c_int, c_uchar, c_void},
    size_t,
};
use rand::{RngCore, SeedableRng};
use rand_hc::Hc128Rng;
use std::{
    convert::TryFrom,
    env,
    fs::{read, remove_file, write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
fn purge_expired_cert(path: &Path) {
    let mut bytes = match read(path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return;
        }
    };

    // mbedtls says "Input must be NULL-terminated".
    bytes.push(0);

    match Certificate::from_pem_multiple(&bytes).map(|certs| {
        let ts = certs
            .iter()
            .last()
            .expect("no certs")
            .not_after()
            .unwrap_or_else(|e| panic!("invalid certificate expiration time: {:?}", e));
        Utc.ymd(ts.year as i32, ts.month as u32, ts.day as u32)
            .and_hms(ts.hour as u32, ts.minute as u32, ts.second as u32)
    }) {
        Ok(not_after) => {
            let utc_now = Utc::now();

            // If certificate expired or expires in the next 24 hours, delete it so it gets
            // regenerated.
            if utc_now + Duration::hours(24) > not_after {
                remove_file(path)
                    .unwrap_or_else(|e| panic!("failed deleting expired cert {:?}: {:?}", path, e));
            }
        }
        Err(_) => {
            // Failed getting expiration date from certificate, delete it so it gets
            // regenerated.
            remove_file(path).unwrap_or_else(|e| {
                panic!("failed deleting non-parseable cert {:?}: {:?}", path, e)
            });
        }
    }
}

fn main() {
    // Generate simulation IAS certificates
    let base_dir = env::var("CARGO_MANIFEST_DIR").expect("Could not read manifest dir");
    let mut data_path = PathBuf::from(base_dir);
    data_path.push("data");
    data_path.push("sim");

    let mut root_anchor_path = data_path.clone();
    root_anchor_path.push("root_anchor.pem");

    let mut signer_key_path = data_path.clone();
    signer_key_path.push("signer.key");

    let mut chain_path = data_path;
    chain_path.push("chain.pem");

    cargo_emit::rerun_if_env_changed!("MC_SEED");
    cargo_emit::rerun_if_changed!(root_anchor_path
        .to_str()
        .expect("Could not stringify root anchor path"));
    cargo_emit::rerun_if_changed!(signer_key_path
        .to_str()
        .expect("Could not stringify signer key path"));
    cargo_emit::rerun_if_changed!(chain_path
        .to_str()
        .expect("Could not stringify signer chain path"));

    purge_expired_cert(&root_anchor_path);
    purge_expired_cert(&chain_path);

    if !(root_anchor_path.exists() && signer_key_path.exists() && chain_path.exists()) {
        const ROOT_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signing CA\0";
        const SIGNER_SUBJECT: &str = "C=US,ST=CA,L=Santa Clara,O=Intel Corporation,CN=Simulation Intel SGX Attestation Report Signer\0";

        let mut serial: [u8; 1] = [1u8];

        let now = Utc::now();
        let end_now = now;
        // Starting 1 hour ago
        let start_time = now - Duration::hours(1);
        // Good for 30 days
        let end_time = end_now + Duration::weeks(1);

        let mut csprng = RngForMbedTls {};

        // ROOT CERTIFICATE
        let mut root_subject_key =
            Pk::generate_rsa(&mut csprng, 3072, 65537).expect("Could not generate privkey");
        let mut root_issuer_key = Pk::from_private_key(
            &root_subject_key
                .write_private_der_vec()
                .expect("Could not export privkey to DER"),
            None,
        )
        .expect("Could not parse privkey from DER");
        // Intermediate authority will be signed by this key.
        let mut signer_issuer_key = Pk::from_private_key(
            &root_subject_key
                .write_private_der_vec()
                .expect("Could not export privkey to DER"),
            None,
        )
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
        let mut signer_subject_key =
            Pk::generate_rsa(&mut csprng, 2048, 65537).expect("Could not generate privkey");
        write(
            signer_key_path,
            signer_subject_key
                .write_private_pem_string()
                .expect("Could not create PEM for signer key."),
        )
        .expect("Could not write signer key PEM to file");

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

        write(chain_path, &(root_cert_pem + &signer_cert_pem)).expect("Unable to write cert chain");
    }

    mc_sgx_build::handle_sgx_sim_feature();
    mc_sgx_build::handle_ias_dev_feature();
}
