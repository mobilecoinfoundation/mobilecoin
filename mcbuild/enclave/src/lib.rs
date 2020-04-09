// Copyright (c) 2018-2020 MobileCoin Inc.

#![feature(external_doc)]
#![doc(include = "../README.md")]

use base64::encode;
use cargo_emit::{rerun_if_changed, rustc_env, warning};
use cargo_metadata::{CargoOpt, Error as MetadataError, Metadata, MetadataCommand};
use failure::Fail;
use mcbuild_sgx_utils::{ConfigBuilder, IasMode, SgxEnvironment, SgxMode, SgxSign};
use mcbuild_utils::{rerun_if_path_changed, CargoBuilder, Environment};
use rand::rngs::OsRng;
use rsa::{errors::Error as RsaError, hash::Hashes, PaddingScheme, PublicKey, RSAPrivateKey};
use sgx_css::{Error as SignatureError, Signature};
use sha2::{digest::Digest, Sha256};
use std::{
    convert::TryFrom,
    fs::{self, File},
    io::{Error as IoError, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::PoisonError,
};

const RSA_DER_PREFIX: [u8; 33] = [
    0x30, 0x82, 0x01, 0xA2, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01,
    0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8F, 0x00, 0x30, 0x82, 0x01, 0x8A, 0x02, 0x82, 0x01, 0x81,
    0x00,
];

/// An enumeration of builder errors.
#[derive(Debug, Fail)]
pub enum Error {
    /// A lock was poisoned.
    #[fail(display = "Lock poisoned")]
    Poison,

    /// There was an error parsing the signature output.
    #[fail(display = "Signature failure: {}", _0)]
    Signature(SignatureError),

    /// There was an error reading the signature file.
    #[fail(display = "I/O error: {}", _0)]
    Io(String),

    /// There was an error executing cargo metadata against the staticlib crate.
    #[fail(display = "Error retrieving metadata about staticlib crate: {}", _0)]
    Metadata(MetadataError),

    /// The SGX signing executable could not dump output.
    #[fail(display = "sgx_sign dump failed")]
    SgxSignDump,

    /// The SGX signing executable could not append the signature to the unsigned binary.
    #[fail(display = "sgx_sign catsig failed")]
    SgxSignCatsig,

    /// The SGX signing executable could not perform a one-shot signature.
    #[fail(display = "sgx_sign sign failed")]
    SgxSign,

    /// The SGX signing executable could not generate the data to be signed.
    #[fail(display = "sgx_sign gendata failed")]
    SgxSignGendata,

    /// There was an error generating an RSA private key.
    #[fail(display = "RSA error: {}", _0)]
    Rsa(RsaError),

    /// The gendata to be signed doesn't match what the given unsigned enclave produces.
    #[fail(display = "The given gendata doesn't match the unsigned enclave")]
    BadGendata,

    /// The enclave staticlib's crate name was in a screwy format.
    #[fail(display = "There was a problem trying to read the enclave staticlib's crate name")]
    TrustedCrateName,

    /// The enclave staticlib's crate name was in a screwy format.
    #[fail(display = "Failed to link the enclave")]
    TrustedLink,

    /// The enclave staticlib's crate name was in a screwy format.
    #[fail(display = "Cargo returned non-zero trying to build the enclave staticlib crate")]
    TrustedBuild,
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

impl From<IoError> for Error {
    fn from(src: IoError) -> Error {
        Error::Io(src.to_string())
    }
}

impl From<RsaError> for Error {
    fn from(src: RsaError) -> Error {
        Error::Rsa(src)
    }
}

impl From<MetadataError> for Error {
    fn from(src: MetadataError) -> Error {
        Error::Metadata(src)
    }
}

/// A builder structure which will configure and build an enclave.
///
/// The basic rule of thumb for provided paths is that it will invent temporary paths for things
/// if they aren't specified
#[derive(Clone, Debug)]
pub struct Builder {
    pub cargo_builder: CargoBuilder,
    pub config_builder: ConfigBuilder,

    name: String,
    staticlib: Metadata,
    signer: SgxSign,
    out_dir: PathBuf,
    target_dir: PathBuf,
    profile_target_dir: PathBuf,
    profile: String,
    libdir: PathBuf,
    linker: PathBuf,
    sgx_mode: SgxMode,
    css: Option<PathBuf>,
    dump: Option<PathBuf>,
    signed_enclave: Option<PathBuf>,
    config_xml: Option<PathBuf>,
    unsigned_enclave: Option<PathBuf>,
    pubkey: Option<PathBuf>,
    privkey: Option<PathBuf>,
    gendata: Option<PathBuf>,
    signature: Option<PathBuf>,
    lds: Option<PathBuf>,
}

impl Builder {
    /// Construct a new enclave builder class, using the given paths.
    pub fn new(
        env: &Environment,
        sgx: &SgxEnvironment,
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

        Ok(Self {
            cargo_builder: CargoBuilder::new(&env, staticlib_dir, false),
            config_builder: ConfigBuilder::default(),
            name: enclave_name.to_owned(),
            staticlib,
            signer: SgxSign::new(&sgx),
            out_dir: env.out_dir().to_owned(),
            target_dir: env.target_dir().to_owned(),
            profile_target_dir: env.profile_target_dir().to_owned(),
            profile: env.profile().to_owned(),
            libdir: sgx.libdir().to_owned(),
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

    /// Set the CSS file path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target dir
    pub fn css(&mut self, css: PathBuf) -> &mut Self {
        self.css = Some(css);
        self
    }

    /// Set the dump file path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target dir
    pub fn dump(&mut self, dump: PathBuf) -> &mut Self {
        self.dump = Some(dump);
        self
    }

    /// Set the signed enclave path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target dir
    pub fn signed_enclave(&mut self, enclave: PathBuf) -> &mut Self {
        self.signed_enclave = Some(enclave);
        self
    }

    /// Set the unsigned enclave path explicitly.
    ///
    /// If unset, one will be derived from the enclave name and profile target dir
    pub fn unsigned_enclave(&mut self, enclave: PathBuf) -> &mut Self {
        self.unsigned_enclave = Some(enclave);
        self
    }

    /// Set the gendata, pubkey, and signature path explicitly, and explicitly request the offline,
    /// catsig process be used.
    ///
    /// If set, the privkey option will be removed.
    ///
    /// If neither and no privkey is set, a private key will be generated from scratch and used to
    /// sign the enclave.
    // TBD: This may cause problems when trying to load the enclave.
    pub fn catsig(&mut self, gendata: PathBuf, pubkey: PathBuf, signature: PathBuf) -> &mut Self {
        self.gendata = Some(gendata);
        self.pubkey = Some(pubkey);
        self.signature = Some(signature);
        self.privkey = None;
        self
    }

    /// Set a privkey path an explicitly request the online one-shot signature process be used.
    ///
    /// If set, any catsig options will be removed.
    ///
    /// If neither privkey nor catsig are called, a private key will be generated from scratch and
    /// used to sign the enclave.
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
    /// If unset, the builder will expect the static crate to provide an "enclave.lds" file. If
    /// that file does not exist, one will be created automatically in the output dir.
    pub fn lds(&mut self, lds: PathBuf) -> &mut Self {
        self.lds = Some(lds);
        self
    }

    /// This method will extract the signature from a signed enclave sigstruct dump.
    ///
    /// If the dump is not found, it will try to extract one from a signed enclave, either in the
    /// output dir or specified in the builder.
    ///
    /// If a signed enclave is not found, it will try to combine a pre-staged signature, pubkey,
    /// generated data, and unsigned enclave.
    ///
    /// If the signature, pubkey, or generated data do not exist, it will generate a new private
    /// key and sign an unsigned enclave.
    ///
    /// If an unsigned enclave does not exist, it will build it.
    pub fn build(&mut self) -> Result<Signature, Error> {
        // Emit correct "rerun-if-changed" diagnostics for cargo
        for package in self.staticlib.packages.iter() {
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
        if self
            .signer
            .dump(&signed_enclave, css_path, &dump_path)
            .status()?
            .success()
        {
            Ok(())
        } else {
            Err(Error::SgxSignDump)
        }
    }

    /// Create the signed enclave binary by applying a signature to an unsigned binary
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

        // Re-create the gendata from the unsigned enclave
        let mut gendata = self.out_dir.join(&self.name);
        gendata.set_extension("dat");
        if !self
            .signer
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

        // If we have been given a private key to use, just sign the enclave in the insecure,
        // one-shot mode
        if let Some(privkey) = &self.privkey {
            return if self
                .signer
                .sign(&unsigned_enclave, &config_xml, &privkey, signed_enclave)
                .status()?
                .success()
            {
                // If we signed an enclave, then it's an artifact.

                let mut signed_artifact = self.profile_target_dir.join(
                    unsigned_enclave
                        .file_name()
                        .expect("Unsigned enclave has no file name"),
                );
                signed_artifact.set_extension("signed.so");
                fs::copy(signed_enclave, &signed_artifact)?;
                Ok(())
            } else {
                Err(Error::SgxSign)
            };
        }

        let (pubkey, signature) =
            if enclave_rebuilt || (self.pubkey.is_none() && self.signature.is_none()) {
                warning!("Generating single-use key for insecure, one-shot signature");

                let mut pubkey = self.out_dir.join(&self.name);
                let mut signature = pubkey.clone();
                pubkey.set_extension("pub");
                signature.set_extension("sig");

                // Get the hash of the gendata output
                let data = fs::read(&gendata)?;
                let mut hasher = Sha256::default();
                hasher.input(&data);
                let digest = hasher.result();

                // Generate a new key and sign the gendata hash
                let mut rng = OsRng::default();
                let private = RSAPrivateKey::new(&mut rng, 3072)?;
                let sig = private.sign(
                    PaddingScheme::PKCS1v15,
                    Some(&Hashes::SHA2_256),
                    digest.as_slice(),
                )?;
                fs::write(&signature, &sig)?;

                let public = private.to_public_key();

                // Build the pubkey DER
                let mut pubkey_der = Vec::with_capacity(512);
                pubkey_der.extend_from_slice(&RSA_DER_PREFIX[..]);
                pubkey_der.append(&mut public.n().to_bytes_be());
                let mut exponent_bytes = public.e().to_bytes_be();
                let exponent_len = exponent_bytes.len() as u8;
                pubkey_der.extend_from_slice(&[0x02, exponent_len]);
                pubkey_der.append(&mut exponent_bytes);

                // Write the PEM
                let mut pubkey_file = File::create(&pubkey)?;
                write!(&mut pubkey_file, "-----BEGIN PUBLIC KEY-----")?;
                write!(&mut pubkey_file, "{}", encode(&pubkey_der))?;
                write!(&mut pubkey_file, "-----END PUBLIC KEY-----")?;
                (pubkey, signature)
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
                (pubkey.clone(), signature.clone())
            };

        if self
            .signer
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
            Ok(())
        } else {
            Err(Error::SgxSignCatsig)
        }
    }

    /// Using the static archive generated from the staticlib crate, link an unsigned dynamic
    /// object.
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

        // "target/foo_enclave"
        let staticlib_target_dir = self.target_dir.join(&self.name);

        // e.g. "foo_enclave_trusted"
        let staticlib_crate_name = self.staticlib.workspace_members[0]
            .repr
            .split_whitespace()
            .next()
            .ok_or(Error::TrustedCrateName)?;

        // "target/name/<profile>/libfoo_enclave_trusted.a" -- not xplatform, but neither is our
        // use of SGX, so meh.
        let mut static_archive_name = "lib".to_owned();
        static_archive_name.push_str(staticlib_crate_name);
        let mut static_archive = staticlib_target_dir.join(&self.profile);
        static_archive.push(static_archive_name);
        static_archive.set_extension("a");
        self.build_enclave()?;

        if Command::new(&self.linker)
            .args(&[
                "-o",
                unsigned_enclave
                    .to_str()
                    .expect("Invalid UTF-8 in unsigned enclave path"),
            ])
            .args(&["--no-undefined", "-nostdlib"])
            .arg(format!("-L{}", self.libdir.display()))
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
            ))
            .status()?
            .success()
        {
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
