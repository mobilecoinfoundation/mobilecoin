// Copyright (c) 2018-2021 The MobileCoin Foundation

#![feature(external_doc)]
#![doc(include = "../README.md")]

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
use pkg_config::{Config, Error as PkgConfigError};
use rand::{thread_rng, RngCore};
use std::{
    collections::HashSet,
    convert::TryFrom,
    fs,
    io::Error as IoError,
    path::{Path, PathBuf},
    process::Command,
    ptr, slice,
    sync::PoisonError,
};

const SGX_LIBS: &[&str] = &["libsgx_urts"];
const SGX_SIMULATION_LIBS: &[&str] = &["libsgx_urts_sim"];
const ENCLAVE_TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";

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
     * There was an error executing cargo metadata against the staticlib
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

    /// The enclave staticlib's crate name was in a screwy format
    TrustedLink,

    /// The enclave staticlib's crate name was in a screwy format
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

    /// A set of PkgConfig configurations and the libraries to use with it
    sgx_version: String,

    /// The cargo metadata of the trusted crate
    staticlib: Metadata,

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

    /// The path to the linker to use
    linker: PathBuf,

    /// The configured SGX mode
    sgx_mode: SgxMode,

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

    /// an option explicit path to a linker script
    lds: Option<PathBuf>,
}

impl Builder {
    /// Construct a new enclave builder class, using the given paths.
    pub fn new(
        env: &Environment,
        sgx: &SgxEnvironment,
        sgx_version: &str,
        enclave_name: &str,
        staticlib_dir: &Path,
    ) -> Result<Self, Error> {
        // Collect metadata about dependencies of enclave
        let mut features_vec = Vec::new();
        if sgx.sgx_mode() == SgxMode::Simulation {
            features_vec.push("sgx-sim".to_owned());
        }
        if sgx.ias_mode() == IasMode::Development {
            features_vec.push("ias-dev".to_owned());
        }

        let staticlib = MetadataCommand::new()
            .cargo_path(env.cargo())
            .current_dir(staticlib_dir)
            .features(CargoOpt::SomeFeatures(features_vec))
            .exec()?;

        let mut cargo_builder = CargoBuilder::new(&env, staticlib_dir, false);

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

        cargo_builder
            .target(ENCLAVE_TARGET_TRIPLE)
            .add_rust_flags(&["-D", "warnings", "-C", &feature_buf]);

        Ok(Self {
            cargo_builder,
            config_builder: ConfigBuilder::default(),
            name: enclave_name.to_owned(),
            staticlib,
            target_arch: env.target_arch().to_owned(),
            out_dir: env.out_dir().to_owned(),
            target_dir: env.target_dir().to_owned(),
            profile_target_dir: env.profile_target_dir().to_owned(),
            profile: env.profile().to_owned(),
            sgx_version: sgx_version.to_owned(),
            linker: env.linker().to_owned(),
            sgx_mode: sgx.sgx_mode(),
            css: None,
            dump: None,
            signed_enclave: None,
            config_xml: None,
            unsigned_enclave: None,
            pubkey: None,
            privkey: None,
            gendata: None,
            signature: None,
            lds: None,
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

    /// Set the LDS path explicitly.
    ///
    /// If unset, the builder will expect the static crate to provide an
    /// "enclave.lds" file. If that file does not exist, one will be created
    /// automatically in the output dir.
    pub fn lds(&mut self, lds: PathBuf) -> &mut Self {
        self.lds = Some(lds);
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
        let mut packages = self.staticlib.packages.clone();
        packages.sort_by_cached_key(|p| p.name.clone());
        // Emit correct "rerun-if-changed" diagnostics for cargo
        for package in packages.iter() {
            // source.is_none implies a local package not from crates.io
            if package.source.is_none() {
                // package.manifest_path has form foo/Cargo.toml, we want to take parent
                // so that we walk the directory containing Cargo.toml
                package.manifest_path.parent().map(rerun_if_path_changed);
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
            warning!("Signed enclave not provided, trying to sign it...");
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

        // Link the static archive into an enclave lib if one doesn't exist already
        let unsigned_enclave = if let Some(unsigned_enclave) = &self.unsigned_enclave {
            rerun_if_changed!(unsigned_enclave
                .as_os_str()
                .to_str()
                .expect("Invalid UTF-8 in unsigned enclave path"));
            unsigned_enclave.clone()
        } else {
            warning!("Unsigned enclave not provided, trying to link a new one...");
            let mut name = "lib".to_owned();
            name.push_str(&self.name);
            let mut unsigned_enclave = self.out_dir.join(&name);
            unsigned_enclave.set_extension("so");
            self.link_unsigned(&unsigned_enclave)?;
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
            self.oneshot(
                &unsigned_enclave,
                &config_xml,
                &private_key,
                &signed_enclave,
            )?;
        } else if enclave_rebuilt || (self.pubkey.is_none() && self.signature.is_none()) {
            warning!("Generating single-use key for insecure, one-shot signature");

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

            self.oneshot(
                &unsigned_enclave,
                &config_xml,
                &private_key,
                &signed_enclave,
            )?;
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
                    &pubkey,
                    &gendata,
                    &signature,
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
            .sign(
                &unsigned_enclave,
                &config_path,
                &private_key,
                output_enclave,
            )
            .status()?
            .success()
        {
            Ok(())
        } else {
            Err(Error::SgxSign)
        }
    }

    /// Using the static archive generated from the staticlib crate, link an
    /// unsigned dynamic object.
    fn link_unsigned(&mut self, unsigned_enclave: &Path) -> Result<(), Error> {
        let lds = if let Some(lds) = &self.lds {
            rerun_if_changed!(lds.as_os_str().to_str().expect("Invalid UTF-8 in LDS path"));
            lds.clone()
        } else {
            let mut lds = self.out_dir.to_owned();
            lds.push(&self.name);
            lds.set_extension("lds");
            lds
        };

        if !lds.exists() {
            fs::write(
                &lds,
                "{
    global:
        g_global_data_sim;
        g_global_data;
        enclave_entry;
        g_peak_heap_used;
        g_peak_rsrv_mem_committed;
    local:
        *;
};
",
            )?;
        }

        let sim_postfix = match self.sgx_mode {
            SgxMode::Hardware => "",
            SgxMode::Simulation => "_sim",
        };

        // "target/mc_foo_enclave"
        let staticlib_target_dir = self.target_dir.join(&self.name);

        // e.g. "mc_foo_enclave_trusted"
        let staticlib_crate_name = self.staticlib.workspace_members[0]
            .repr
            .split_whitespace()
            .next()
            .ok_or(Error::TrustedCrateName)?;

        // "target/name/<profile>/libmc_foo_enclave_trusted.a" -- not xplatform, but
        // neither is our use of SGX, so meh.
        let mut static_archive_name = "lib".to_owned();
        // libnames are not kebab, crate names are
        static_archive_name.push_str(&staticlib_crate_name.replace("-", "_"));

        let mut static_archive = staticlib_target_dir.join(ENCLAVE_TARGET_TRIPLE);
        static_archive.push(&self.profile);
        static_archive.push(static_archive_name);
        static_archive.set_extension("a");
        self.build_enclave()?;

        // Note: Some of the linker flags here are important for security [1]
        //
        // -noexecstack makes the stack not executable. This is also called NX [3]
        //
        // -pie is relevant to making sure there are no relocatable text sections
        // in the enclave. If there are relocatable text sections, then those
        // pages will writeable. See discussion in [2] second paragraph.
        //
        // -relro is also relevant to that -- relro means that relocated text
        //  segments will be made read-only after relocation. But there is no mechanism
        //  for that in SGX [4]. So I think perhaps relro is not needed with -pie,
        //  but we should include it if it is in [1], and it likely has no effect.
        //
        // -now means that the usual "lazily resolve symbol on first use" strategy
        //  for shared libraries is disabled and all symbols get resolved immediately on
        // load.  Since the enclave is ultimatley a self-contained static blob,
        // we don't need or  want any of those trampolines. [4]
        //
        // Note: [2] suggests in the last sentence that the sgx_sign utility
        // *should* issue a warning if there are any text relocations.
        // We might also want to use `checksec.sh` [3] against the signed enclave (?)
        // because that can also check for PIE and for NX.
        //
        // [1] https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleEnclave/Makefile#L135
        // [2] https://software.intel.com/sites/default/files/managed/ae/48/Software-Guard-Extensions-Enclave-Writers-Guide.pdf), in section 10, page 30
        // [3] https://github.com/slimm609/checksec.sh
        // [4] man ld(1)

        let mut command = Command::new(&self.linker);

        command
            .args(&[
                "-o",
                unsigned_enclave
                    .to_str()
                    .expect("Invalid UTF-8 in unsigned enclave path"),
            ])
            .args(&["-z", "relro", "-z", "now", "-z", "noexecstack"])
            .args(&["--no-undefined", "-nostdlib"]);

        let mut config = Config::new();
        config
            .exactly_version(&self.sgx_version)
            .print_system_libs(true)
            .cargo_metadata(false)
            .env_metadata(true);

        let lib_paths = if self.sgx_mode == SgxMode::Simulation {
            SGX_SIMULATION_LIBS
        } else {
            SGX_LIBS
        }
        .iter()
        .map(|libname| Ok(config.probe(libname)?.link_paths))
        .collect::<Result<Vec<Vec<PathBuf>>, PkgConfigError>>()?
        .into_iter()
        .flatten()
        .collect::<HashSet<PathBuf>>();

        for path in lib_paths {
            if self.sgx_mode == SgxMode::Simulation {
                let cve_load = path.join("cve_2020_0551_load");
                if cve_load.exists() {
                    command.arg(format!("-L{}", cve_load.display()));
                }
            }
            command.arg(format!("-L{}", path.display()));
        }

        command
            .args(&[
                "--whole-archive",
                &format!("-lsgx_trts{}", sim_postfix),
                "--no-whole-archive",
            ])
            .args(&[
                "--start-group",
                "-lsgx_tstdc",
                "-lsgx_tcxx",
                "-lsgx_tcrypto",
                &format!("-lsgx_tservice{}", sim_postfix),
                static_archive
                    .to_str()
                    .expect("Invalid UTF-8 in enclave staticlib filename"),
                "--end-group",
            ])
            .args(&["-Bstatic", "-Bsymbolic", "--no-undefined"])
            .args(&["-pie", "-eenclave_entry", "--export-dynamic"])
            .args(&["--defsym", "__ImageBase=0"])
            .arg("--gc-sections")
            .arg(format!(
                "--version-script={}",
                lds.to_str()
                    .expect("Invalid UTF-8 in linker version-script filename")
            ));

        if command.status()?.success() {
            let unsigned_artifact = self.profile_target_dir.join(
                unsigned_enclave
                    .file_name()
                    .expect("Could not figure out filename from unsigned archive path"),
            );
            fs::copy(unsigned_enclave, unsigned_artifact)?;
            Ok(())
        } else {
            Err(Error::TrustedLink)
        }
    }

    /// Run cargo to build the static archive.
    fn build_enclave(&mut self) -> Result<(), Error> {
        if self.cargo_builder.construct().status()?.success() {
            Ok(())
        } else {
            Err(Error::TrustedBuild)
        }
    }
}
