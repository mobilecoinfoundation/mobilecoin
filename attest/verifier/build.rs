// Copyright (c) 2018-2023 The MobileCoin Foundation

use chrono::{offset::Utc, DateTime, Datelike, Duration, SecondsFormat::Secs, Timelike};
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
    ecdsa::{signature::Signer, Signature, SigningKey},
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

use p256::pkcs8::{
    der::{
        asn1::{Int, OctetString, SequenceOf},
        Any, Encode, EncodeValue, SliceWriter, Tag, Tagged,
    },
    ObjectIdentifier,
};

const FMSPC: &str = "0123456789AB";

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
const QE_IDENTITY_FILENAME: &str = "qe_identity.json";
const TCB_INFO_FILENAME: &str = "tcb_info.json";

const GENERATED_FILENAMES: &[&str] = &[
    ROOT_ANCHOR_FILENAME,
    SIGNER_KEY_FILENAME,
    CHAIN_FILENAME,
    QE_IDENTITY_FILENAME,
    TCB_INFO_FILENAME,
];

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
    /// The optional extensions (oid, value)
    extensions: Vec<(Vec<u8>, Vec<u8>)>,
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
    let qe_identity_path = data_path.join(QE_IDENTITY_FILENAME);
    let tcb_info_path = data_path.join(TCB_INFO_FILENAME);

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
        extensions: vec![],
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
        validity: validity.clone(),
        extensions: vec![dcap_extensions()],
    };
    let (signer_cert_pem, signer_key) = create_certificate(issuer, &subject);
    write(chain_path, signer_cert_pem + &root_cert_pem).expect("Unable to write cert chain");
    write_signing_key(signer_key_path, &signer_key);

    generate_qe_identity(qe_identity_path, &validity, &signer_key);
    generate_tcb_info(tcb_info_path, &validity, &signer_key);
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
    for (oid, value) in subject.extensions.iter() {
        builder
            .extension(oid, value, false)
            .expect("Could not set extension");
    }
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

/// Returns the mandatory DCAP OID extensions, `(oid, bytes)`
///
/// The extensions (and OID values) are documented at
/// <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf#%5B%7B%22num%22%3A193%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C690%2C0%5D>
fn dcap_extensions() -> (Vec<u8>, Vec<u8>) {
    // We use 0 for all the SVNs in the unlikely event this cert tries to
    // get used to verify against real TCB info, the real TCB Info will have a
    // higher SVN. The IDs and FMSPC uses an incrementing sequence of numbers
    // hoping to avoid real values seen in the wild.

    let ppid = sequence_of_2(
        "1.2.840.113741.1.13.1.1",
        OctetString::new("1234562890123456").expect("failed to create octet string"),
    );

    let mut tcb_sequence = SequenceOf::<_, 18>::new();
    for i in 1..=16 {
        let comp_svn = sequence_of_2(
            &format!("1.2.840.113741.1.13.1.2.{i}"),
            Int::new(&[0]).expect("failed to create integer"),
        );
        tcb_sequence
            .add(comp_svn)
            .expect("failed to add component sequence");
    }
    let pce_svn = sequence_of_2(
        "1.2.840.113741.1.13.1.2.17",
        Int::new(&[0]).expect("failed to create integer"),
    );
    tcb_sequence.add(pce_svn).expect("failed to add pce svn");
    let cpu_svn = sequence_of_2(
        "1.2.840.113741.1.13.1.2.18",
        OctetString::new("0000000000000000").expect("failed to create octet string"),
    );
    tcb_sequence.add(cpu_svn).expect("failed to add cpu svn");
    let tcb = sequence_of_2("1.2.840.113741.1.13.1.2", tcb_sequence);

    let pce_id = sequence_of_2(
        "1.2.840.113741.1.13.1.3",
        OctetString::new("12").expect("failed to create octet string"),
    );
    let fmspc = sequence_of_2(
        "1.2.840.113741.1.13.1.4",
        OctetString::new(hex::decode(FMSPC).expect("failed to decode FMSPC"))
            .expect("failed to create octet string"),
    );
    let sgx_type = sequence_of_2(
        "1.2.840.113741.1.13.1.4",
        Any::new(
            Tag::Enumerated,
            // Zero is `Standard`
            Int::new(&[0]).expect("failed to create integer").as_bytes(),
        )
        .expect("failed to create any"),
    );
    let mut extensions_sequence = SequenceOf::<_, 5>::new();
    for extension in [ppid, tcb, pce_id, fmspc, sgx_type] {
        extensions_sequence
            .add(extension)
            .expect("failed to add extension");
    }

    (
        ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1")
            .as_bytes()
            .to_vec(),
        extensions_sequence
            .to_der()
            .expect("failed to serialize extensions sequence"),
    )
}

/// Create a 2 element SEQUENCE
///
/// The extension format is:
///
///    extension ::= SEQUENCE {
///         oid OID,
///         value ANY DEFINED BY oid }
fn sequence_of_2<T: EncodeValue + Tagged>(oid: impl AsRef<str>, value: T) -> SequenceOf<Any, 2> {
    let oid = ObjectIdentifier::new(oid.as_ref()).expect("failed to create oid");

    // Most types have a `value()` method, but it isn't on a trait. So to keep this
    // function generic we leverage the `EncodeValue` trait, which require a bit
    // more work to get to the value.
    let length = u32::from(value.value_len().expect("failed to get value len"));
    let mut buf = vec![0; length as usize];
    let mut writer = SliceWriter::new(buf.as_mut_slice());
    value
        .encode_value(&mut writer)
        .expect("failed to encode value");

    let mut sequence = SequenceOf::<_, 2>::new();
    sequence
        .add(Any::new(oid.tag(), oid.as_bytes()).expect("failed to create any"))
        .expect("failed to add oid");
    sequence
        .add(Any::new(value.tag(), buf).expect("failed to create any"))
        .expect("failed to add oid");
    sequence
}

/// Update the TCB info file if it's expired or doesn't exist.
fn generate_tcb_info(tcb_path: impl AsRef<Path>, validity: &Validity, signing_key: &SigningKey) {
    // The example TCB info from
    // <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>
    // with unnecessary fields omitted.
    let tcb_info = format!(
        r#"
        {{
          "id": "SGX",
          "version": 3,
          "issueDate": "{}",
          "nextUpdate": "{}",
          "fmspc": "{}",
          "pceId": "0000",
          "tcbType": 0,
          "tcbEvaluationDataNumber": 12,
          "tcbLevels": [
            {{
              "tcb": {{
                "sgxtcbcomponents": [
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }},
                  {{
                    "svn": 0
                  }}
                ],
                "pcesvn": 0
              }},
              "tcbDate": "2021-11-10T00:00:00Z",
              "tcbStatus": "UpToDate"
            }}
          ]
        }}"#,
        validity.not_before.to_rfc3339_opts(Secs, true),
        validity.not_after.to_rfc3339_opts(Secs, true),
        FMSPC
    );

    sign_and_write_json(tcb_path, signing_key, &tcb_info, "tcbInfo");
}

/// Update the QE identity file if it's expired or doesn't exist.
fn generate_qe_identity(
    qe_identity_path: impl AsRef<Path>,
    validity: &Validity,
    signing_key: &SigningKey,
) {
    // The example QE identity from
    // <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
    // with unnecessary fields omitted.
    let qe_identity = format!(
        r#"
        {{
          "id": "QE",
          "version": 2,
          "issueDate": "{}",
          "nextUpdate": "{}",
          "tcbEvaluationDataNumber": 12,
          "miscselect": "00000000",
          "miscselectMask": "FFFFFFFF",
          "attributes": "00000000000000000000000000000000",
          "attributesMask": "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
          "mrsigner": "1234567890ABCDEFFEDCBA09876543211234567890ABCDEFFEDCBA0987654321",
          "isvprodid": 0,
          "tcbLevels": [
            {{
              "tcb": {{
                "isvsvn": 0
              }},
              "tcbDate": "2021-11-10T00:00:00Z",
              "tcbStatus": "UpToDate"
            }}
          ]
        }}"#,
        validity.not_before.to_rfc3339_opts(Secs, true),
        validity.not_after.to_rfc3339_opts(Secs, true)
    );
    sign_and_write_json(
        qe_identity_path,
        signing_key,
        &qe_identity,
        "enclaveIdentity",
    );
}

fn sign_and_write_json(
    json_path: impl AsRef<Path>,
    signing_key: &SigningKey,
    json: &str,
    json_tag: &str,
) {
    let mut json_string = json.to_owned();
    // The signature is sensitive to the whitespace or lack thereof. The
    // <https://api.portal.trustedservices.intel.com/documentation> says:
    //      "signature calculated over tcbInfo body without whitespaces"
    // Both the qe_identity and tcb_info json have no intermediate whitespace.
    json_string.retain(|c| !c.is_whitespace());
    let json_signature = (signing_key as &dyn Signer<Signature>).sign(json_string.as_bytes());

    let hex_signature = hex::encode(json_signature.to_bytes());
    let json_with_signature =
        format!("{{\"{json_tag}\":{json_string},\"signature\":\"{hex_signature}\"}}");
    write(json_path, json_with_signature).expect("Unable to write json");
}
