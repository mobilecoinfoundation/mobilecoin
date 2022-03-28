// Copyright (c) 2018-2021 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use cargo_emit::{rerun_if_changed, rustc_env, warning};
use cargo_metadata::{CargoOpt, Error as MetadataError, Metadata, MetadataCommand};
use displaydoc::Display;
use mbedtls::{pk::Pk, rng::RngCallback};
use mbedtls_sys::types::{
    raw_types::{c_int, c_uchar, c_void},
    size_t,
};
use mc_sgx_css::{Error as SignatureError, Signature};
use mc_util_build_script::{rerun_if_path_changed, CargoBuilder, Environment};
use mc_util_build_sgx::{ConfigBuilder, IasMode, SgxEnvironment, SgxMode, SgxSign};
use pkg_config::Error as PkgConfigError;
use rand::{thread_rng, RngCore};
use std::{
    convert::TryFrom,
    fs,
    io::Error as IoError,
    path::{Path, PathBuf},
    ptr, slice,
    sync::PoisonError,
};

const ENCLAVE_TARGET_TRIPLE: &str = "x86_64-mobilecoin-none-sgx";

struct ThreadRngForMbedTls;

impl RngCallback for ThreadRngForMbedTls {
    #[inline(always)]
    unsafe extern "C" fn call(_: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
        let outbuf = slice::from_raw_parts_mut(data, len);
        let mut csprng = thread_rng();
        csprng.fill_bytes(outbuf);
        0
    }

    fn data_ptr(&self) -> *mut c_void {
        ptr::null_mut()
    }
}

/// An enumeration of builder errors.
#[derive(Debug, Display)]
pub enum Error {
    /// A lock was poisoned
    Poison,

    /// There was an error parsing the signature output: {0}
    Signature(SignatureError),

    /// There was an error reading the signature file: {0}
    Io(String),

    /**
     * There was an error executing cargo metadata against the enclave
     * crate: {0}
     */
    Metadata(MetadataError),

    /// There was an error executing pkg-config
    PkgConfig(PkgConfigError),

    /// The SGX signing executable could not dump output
    SgxSignDump,

    /**
     * The SGX signing executable could not append the signature to the
     * unsigned binary
     */
    SgxSignCatsig,

    /// The SGX signing executable could not perform a one-shot signature
    SgxSign,

    /// The SGX signing executable could not generate the data to be signed
    SgxSignGendata,

    /**
     * The gendata to be signed doesn't match what the given unsigned
     * enclave produces
     */
    BadGendata,

    /// The enclave staticlib's crate name was in a screwy format
    TrustedCrateName,

    /// The enclave crate failed to build
    TrustedBuild,
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Error {
        Error::Io(src.to_string())
    }
}

impl From<MetadataError> for Error {
    fn from(src: MetadataError) -> Error {
        Error::Metadata(src)
    }
}

impl From<PkgConfigError> for Error {
    fn from(src: PkgConfigError) -> Error {
        Error::PkgConfig(src)
    }
}

impl<T> From<PoisonError<T>> for Error {
    fn from(_src: PoisonError<T>) -> Error {
        Error::Poison
    }
}

impl From<SignatureError> for Error {
    fn from(src: SignatureError) -> Error {
        Error::Signature(src)
    }
}

/// A builder structure which will configure and build an enclave.
///
/// The basic rule of thumb for provided paths is that it will invent temporary
/// paths for things if they aren't specified
#[derive(Clone, Debug)]
pub struct Builder {
    /// The cargo command builder
    cargo_builder: CargoBuilder,

    /// The SGX configuration XML builder
    pub config_builder: ConfigBuilder,

    /// The name of the enclave
    name: String,

    /// The cargo metadata of the enclave crate
    enclave_crate: Metadata,

    /// The OUT_DIR path
    out_dir: PathBuf,

    /// The target architecture
    target_arch: String,

    /// The CARGO_TARGET_DIR path
    target_dir: PathBuf,

    /// The CARGO_TARGET_DIR/profile path
    profile_target_dir: PathBuf,

    /// The name of the profile we're building for
    profile: String,

    /// An optional explicit path to an existing CSS (sigstruct) file
    css: Option<PathBuf>,

    /// An optional explicit path to an existing sigstruct text dump
    dump: Option<PathBuf>,

    /// An optional explicit path to a pre-signed enclave
    signed_enclave: Option<PathBuf>,

    /// An optional explicit path to a pre-existing SGX config XML file
    config_xml: Option<PathBuf>,

    /// An optional explicit path to a pre-existing unsigned enclave binary
    unsigned_enclave: Option<PathBuf>,

    /// An optional explicit path to a pre-existing public key
    pubkey: Option<PathBuf>,

    /// An optional explicit path to a pre-existing private key
    privkey: Option<PathBuf>,

    /// An optional explicit path to pre-existing data under signature
    gendata: Option<PathBuf>,

    /// An optional explicit path to a file containing a detached signature
    signature: Option<PathBuf>,
}

impl Builder {
    /// Construct a new enclave builder class, using the given paths.
    pub fn new(
        env: &Environment,
        sgx: &SgxEnvironment,
        enclave_name: &str,
        enclave_dir: &Path,
    ) -> Result<Self, Error> {
        // Collect metadata about dependencies of enclave
        let mut features_vec = Vec::new();
        if sgx.sgx_mode() == SgxMode::Simulation {
            features_vec.push("sgx-sim".to_owned());
        }
        if sgx.ias_mode() == IasMode::Development {
            features_vec.push("ias-dev".to_owned());
        }

        let enclave_crate = MetadataCommand::new()
            .cargo_path(env.cargo())
            .current_dir(enclave_dir)
            .features(CargoOpt::SomeFeatures(features_vec))
            .exec()?;

        let mut cargo_builder = CargoBuilder::new(env, enclave_dir, false);

        // copy our target features to the enclave's build
        let features = env.target_features();
        let mut feature_buf = String::with_capacity(features.len() * 32);
        feature_buf.push_str("target-feature=+lvi-cfi,+lvi-load-hardening");
        for feature in features {
            feature_buf.push(',');
            feature_buf.push('+');
            // Cleanup cargo's nonsense.
            match feature.as_str() {
                "cmpxchg16b" => feature_buf.push_str("cx16"),
                "pclmulqdq" => feature_buf.push_str("pclmul"),
                "rdrand" => feature_buf.push_str("rdrnd"),
                "bmi1" => feature_buf.push_str("bmi"),
                other => feature_buf.push_str(other),
            }
        }

        cargo_builder.add_rust_flags(&["-D", "warnings", "-C", &feature_buf]);

        Ok(Self {
            cargo_builder,
            config_builder: ConfigBuilder::default(),
            name: enclave_name.to_owned(),
            enclave_crate,
            target_arch: env.target_arch().to_owned(),
            out_dir: env.out_dir().to_owned(),
            target_dir: env.target_dir().to_owned(),
            profile_target_dir: env.profile_target_dir().to_owned(),
            profile: env.profile().to_owned(),
            css: None,
            dump: None,
            signed_enclave: None,
            config_xml: None,
            unsigned_enclave: None,
            pubkey: None,
            privkey: None,
            gendata: None,
            signature: None,
        })
    }

    /// Set a new "base" target dir to use when building an enclave
    pub fn target_dir(&mut self, target_dir: &Path) -> &mut Self {
        self.cargo_builder.target_dir(target_dir);
        self
    }

    /// Add rust flags to use when building an enclave.
    ///
    /// Note that the target and required compiler mitigations will be set
    /// already.
    pub fn add_rust_flags(&mut self, flags: &[&str]) -> &mut Self {
        self.cargo_builder.add_rust_flags(flags);
        self
    }

    /// Set the CSS file path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target
    /// dir
    pub fn css(&mut self, css: PathBuf) -> &mut Self {
        self.css = Some(css);
        self
    }

    /// Set the dump file path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target
    /// dir
    pub fn dump(&mut self, dump: PathBuf) -> &mut Self {
        self.dump = Some(dump);
        self
    }

    /// Set the signed enclave path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target
    /// dir
    pub fn signed_enclave(&mut self, enclave: PathBuf) -> &mut Self {
        self.signed_enclave = Some(enclave);
        self
    }

    /// Set the unsigned enclave path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target
    /// dir
    pub fn unsigned_enclave(&mut self, enclave: PathBuf) -> &mut Self {
        self.unsigned_enclave = Some(enclave);
        self
    }

    /// Set the gendata, pubkey, and signature path explicitly, and explicitly
    /// request the offline, catsig process be used.
    ///
    /// If set, the privkey option will be removed.
    ///
    /// If neither and no privkey is set, a private key will be generated from
    /// scratch and used to sign the enclave.
    // TBD: This may cause problems when trying to load the enclave.
    pub fn catsig(&mut self, gendata: PathBuf, pubkey: PathBuf, signature: PathBuf) -> &mut Self {
        self.gendata = Some(gendata);
        self.pubkey = Some(pubkey);
        self.signature = Some(signature);
        self.privkey = None;
        self
    }

    /// Set a privkey path an explicitly request the online one-shot signature
    /// process be used.
    ///
    /// If set, any catsig options will be removed.
    ///
    /// If neither privkey nor catsig are called, a private key will be
    /// generated from scratch and used to sign the enclave.
    // TBD: This may cause problems when trying to load the enclave.
    pub fn privkey(&mut self, privkey: PathBuf) -> &mut Self {
        self.privkey = Some(privkey);
        self.gendata = None;
        self.pubkey = None;
        self.signature = None;
        self
    }

    /// This method will extract the signature from a signed enclave sigstruct
    /// dump.
    ///
    /// If the dump is not found, it will try to extract one from a signed
    /// enclave, either in the output dir or specified in the builder.
    ///
    /// If a signed enclave is not found, it will try to combine a pre-staged
    /// signature, pubkey, generated data, and unsigned enclave.
    ///
    /// If the signature, pubkey, or generated data do not exist, it will
    /// generate a new private key and sign an unsigned enclave.
    ///
    /// If an unsigned enclave does not exist, it will build it.
    pub fn build(&mut self) -> Result<Signature, Error> {
        let mut packages = self.enclave_crate.packages.clone();
        packages.sort_by_cached_key(|p| p.name.clone());
        // Emit correct "rerun-if-changed" diagnostics for cargo
        for package in packages.iter() {
            // source.is_none implies a local package not from crates.io
            if package.source.is_none() {
                // package.manifest_path has form foo/Cargo.toml, we want to take parent
                // so that we walk the directory containing Cargo.toml
                if let Some(utf8_path) = package.manifest_path.parent() {
                    rerun_if_path_changed(utf8_path.as_std_path());
                }
            }
        }

        let css_path = if let Some(css) = &self.css {
            rerun_if_changed!(css.as_os_str().to_str().expect("Invalid UTF-8 in CSS path"));
            css.canonicalize()?
        } else {
            let mut css_path = self.out_dir.join(&self.name);
            css_path.set_extension("css");
            self.create_css(&css_path)?;
            css_path
        };

        rustc_env!(
            "MCBUILD_ENCLAVE_CSS_PATH",
            "{}",
            css_path
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in CSS path")
        );

        let retval = Signature::try_from(fs::read(&css_path)?.as_slice())?;

        // Treat the CSS file as an artifact for future builds
        let mut artifact = self.profile_target_dir.join(&self.name);
        artifact.set_extension("css");
        if css_path != artifact {
            fs::copy(&css_path, artifact)?;
        }

        Ok(retval)
    }

    /// Get a CSS file dump to the path
    fn create_css(&mut self, css_path: &Path) -> Result<(), Error> {
        let signed_enclave = if let Some(signed_enclave) = &self.signed_enclave {
            rerun_if_changed!(signed_enclave
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in signed enclave path"));
            signed_enclave.clone()
        } else {
            warning!(
                "Signed enclave {} not provided, trying to sign it...",
                self.name
            );
            let mut signed_enclave_name = "lib".to_owned();
            signed_enclave_name.push_str(&self.name);
            let mut signed_enclave = self.out_dir.join(&signed_enclave_name);
            signed_enclave.set_extension("signed.so");
            self.sign_enclave(&signed_enclave)?;
            signed_enclave
        };

        let mut dump_path = self.out_dir.join(&self.name);
        dump_path.set_extension("dump");
        if SgxSign::new(&self.target_arch)?
            .dump(&signed_enclave, css_path, &dump_path)
            .status()?
            .success()
        {
            Ok(())
        } else {
            Err(Error::SgxSignDump)
        }
    }

    /// Create the signed enclave binary by applying a signature to an unsigned
    /// binary
    fn sign_enclave(&mut self, signed_enclave: &Path) -> Result<(), Error> {
        // Write the configuration file if one isn't provided
        let config_xml = if let Some(config_xml) = &self.config_xml {
            rerun_if_changed!(config_xml
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in config_xml pathbuf"));
            config_xml.clone()
        } else {
            let mut config_xml = self.out_dir.join(&self.name);
            config_xml.set_extension("config.xml");
            self.config_builder.write_to_file(&config_xml);
            config_xml
        };

        let mut enclave_rebuilt = false;

        // Build the unsigned enclave if one doesn't exist already
        let unsigned_enclave = if let Some(unsigned_enclave) = &self.unsigned_enclave {
            rerun_if_changed!(unsigned_enclave
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in unsigned enclave path"));
            unsigned_enclave.clone()
        } else {
            warning!(
                "Unsigned enclave {} not provided, trying to build a new one...",
                self.name
            );
            let unsigned_enclave = self.out_dir.join(dynamic_library_filename(&self.name));
            self.build_enclave(&unsigned_enclave)?;
            enclave_rebuilt = true;
            unsigned_enclave
        };

        let gendata = if let Some(gendata) = &self.gendata {
            rerun_if_changed!(gendata
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in GENDATA path"));
            gendata.clone()
        } else {
            // Re-create the gendata from the unsigned enclave
            let mut gendata = self.out_dir.join(&self.name);
            gendata.set_extension("dat");
            if !SgxSign::new(&self.target_arch)?
                .gendata(&unsigned_enclave, &config_xml, &gendata)
                .status()?
                .success()
            {
                return Err(Error::SgxSignGendata);
            }

            // The generated data is an artifact, so copy it to our target profile dir
            let mut gendata_artifact = self.profile_target_dir.join(&self.name);
            gendata_artifact.set_extension("dat");
            fs::copy(&gendata, gendata_artifact)?;

            gendata
        };

        // The signed enclave is also an artifact, so we will copy it to the target
        // profile dir
        let mut signed_artifact = self.profile_target_dir.join(
            unsigned_enclave
                .file_name()
                .expect("Unsigned enclave has no file name"),
        );
        signed_artifact.set_extension("signed.so");

        // If we have been given a private key to use, just sign the enclave in the
        // insecure, one-shot mode
        if let Some(private_key) = &self.privkey.clone() {
            self.oneshot(&unsigned_enclave, &config_xml, private_key, signed_enclave)?;
        } else if enclave_rebuilt || (self.pubkey.is_none() && self.signature.is_none()) {
            warning!(
                "Generating single-use key for insecure, one-shot signature of {}",
                self.name
            );

            let mut csprng = ThreadRngForMbedTls {};

            let mut privkey =
                Pk::generate_rsa(&mut csprng, 3072, 3).expect("Could not generate privkey");

            let mut private_key = self.out_dir.join(&self.name);
            private_key.set_extension("key");

            fs::write(
                &private_key,
                privkey
                    .write_private_pem_string()
                    .expect("Could not write PEM string for private key"),
            )
            .expect("Could not write PEM string to private key file");

            self.oneshot(&unsigned_enclave, &config_xml, &private_key, signed_enclave)?;
        } else {
            let pubkey = self.pubkey.as_ref().unwrap();
            let signature = self.signature.as_ref().unwrap();
            rerun_if_changed!(signature
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in signature path"));
            rerun_if_changed!(pubkey
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in pubkey path"));

            if !SgxSign::new(&self.target_arch)?
                .catsig(
                    &unsigned_enclave,
                    &config_xml,
                    pubkey,
                    &gendata,
                    signature,
                    signed_enclave,
                )
                .status()?
                .success()
            {
                return Err(Error::SgxSignCatsig);
            }
        }

        fs::copy(signed_enclave, &signed_artifact)?;
        Ok(())
    }

    fn oneshot(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        private_key: &Path,
        output_enclave: &Path,
    ) -> Result<(), Error> {
        if SgxSign::new(&self.target_arch)?
            .sign(unsigned_enclave, config_path, private_key, output_enclave)
            .status()?
            .success()
        {
            Ok(())
        } else {
            Err(Error::SgxSign)
        }
    }

    /// Build the enclave outputting it to `unsigned_enclave`.
    fn build_enclave(&mut self, unsigned_enclave: &Path) -> Result<(), Error> {
        self.run_cargo()?;

        let library_dir = self.target_dir.join(&self.name);
        let library_crate_name = self.enclave_crate.workspace_members[0]
            .repr
            .split_whitespace()
            .next()
            .ok_or(Error::TrustedCrateName)?;

        let mut full_library_path = library_dir.join(ENCLAVE_TARGET_TRIPLE);
        full_library_path.push(&self.profile);
        full_library_path.push(library_crate_name);
        fs::copy(full_library_path, unsigned_enclave)?;

        Ok(())
    }

    /// Run cargo to build the enclave crate.
    fn run_cargo(&mut self) -> Result<(), Error> {
        if self.cargo_builder.construct().status()?.success() {
            Ok(())
        } else {
            Err(Error::TrustedBuild)
        }
    }
}

/// Create a filename for a dynamic library.  The returned library name will
/// have the platform appropriate prefix and suffix.
///
/// Note: currently only supports *nix
///
/// Arguments:
///
/// * `bare_name`: The bare library name, which will have the necessary prefix
///   and suffix added.
fn dynamic_library_filename(bare_name: &str) -> PathBuf {
    let mut basename = "lib".to_owned();
    basename.push_str(bare_name);
    let mut full_name = PathBuf::from(basename);
    full_name.set_extension("so");
    full_name
}
