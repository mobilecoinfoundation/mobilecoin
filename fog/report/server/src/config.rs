// Copyright (c) 2018-2022 The MobileCoin Foundation
#![deny(missing_docs)]

//! Configuration parameters for ReportServer

use clap::Parser;
use displaydoc::Display;
use mc_crypto_keys::{DistinguishedEncoding, Ed25519Pair, Ed25519Private, Ed25519Public, KeyError};
use mc_crypto_x509_utils::{ChainError, X509CertificateChain, X509CertificateIter};
use mc_fog_sql_recovery_db::SqlRecoveryDbConnectionConfig;
use mc_util_uri::{AdminUri, FogUri};
use pem::PemError;
use serde::Serialize;
use std::{fs, io::Error as IoError, path::PathBuf, result::Result as StdResult};
use x509_signature::X509Certificate;

/// Configuration options for the report server
#[derive(Clone, Debug, Parser, Serialize)]
#[clap(
    name = "report-server",
    about = "Ingest Attestation Report Server.",
    version
)]
pub struct Config {
    /// gRPC listening URI for client requests.
    #[clap(long, env = "MC_CLIENT_LISTEN_URI")]
    pub client_listen_uri: FogUri,

    /// Internal admin server used for metrics/debugging.
    #[clap(long, env = "MC_ADMIN_LISTEN_URI")]
    pub admin_listen_uri: Option<AdminUri>,

    /// The path to an X509 certificate chain in PEM format.
    #[clap(long, parse(from_os_str), env = "MC_SIGNING_CHAIN")]
    pub signing_chain: PathBuf,

    /// The path to the signing key.
    #[clap(long, parse(from_os_str), env = "MC_SIGNING_KEY")]
    pub signing_key: PathBuf,

    /// Postgres config
    #[clap(flatten)]
    pub postgres_config: SqlRecoveryDbConnectionConfig,
}

/// An enumeration of errors which can occur while reading configuration from
/// disk
#[derive(Debug, Display)]
pub enum Error {
    /**
     * One of the files containing cryptographic material could not be read:
     * {0}
     */
    Io(IoError),
    /// The certificate chain could not be parsed as PEM: {0}
    Pem(PemError),
    /// The certificate chain was not valid: {0}
    Chain(ChainError),
    /// There was an error parsing the private key file: {0}
    Key(KeyError),
    /**
     * The last validated cert in the given chain contains a public key
     * which  doesn't correspond to the given private key
     */
    ChainKeyMismatch,
}

impl From<ChainError> for Error {
    fn from(src: ChainError) -> Self {
        Error::Chain(src)
    }
}

impl From<IoError> for Error {
    fn from(src: IoError) -> Self {
        Error::Io(src)
    }
}

impl From<PemError> for Error {
    fn from(src: PemError) -> Self {
        Error::Pem(src)
    }
}

impl From<KeyError> for Error {
    fn from(src: KeyError) -> Self {
        Error::Key(src)
    }
}

/// A type alias for error results when loading materials
type Result<T> = StdResult<T, Error>;

/// The cryptographic materials to be loaded from configured file paths
#[derive(Debug)]
pub struct Materials {
    /// A list of DER encoded X509 certificates parsed from a PEM string
    pub(crate) chain: Vec<Vec<u8>>,
    /// A keypair loaded from a PEM-encoded private key
    pub(crate) signing_keypair: Ed25519Pair,
}

impl Materials {
    /// Construct from a pair of PEM strings
    pub fn from_pems(pem_chain: String, pem_privkey: String) -> Result<Self> {
        let signing_keypair =
            Ed25519Private::try_from_der(&pem::parse(pem_privkey)?.contents)?.into();
        Self::from_pem_keypair(pem_chain, signing_keypair)
    }

    /// Construct from a PEM chain and a keypair
    pub fn from_pem_keypair(pem_chain: String, signing_keypair: Ed25519Pair) -> Result<Self> {
        // Convert the PEM chain into the DER chain we want to use
        let chain = pem::parse_many(pem_chain)
            .expect("Could not parse PEM chain")
            .into_iter()
            .map(|pem| pem.contents)
            .collect();

        Self::from_ders_keypair(chain, signing_keypair)
    }

    /// Construct from a DER bytes list and a keypair
    pub fn from_ders_keypair(chain: Vec<Vec<u8>>, signing_keypair: Ed25519Pair) -> Result<Self> {
        // Verify the chain is reasonable (we throw this work away, but it's better to
        // verify this stuff and fail here than press ahead and generate responses that
        // don't validate).
        //
        // FIXME: Implement X509CertificateIterable for Vec<Vec<u8>>, simplify this
        //        dramatically.
        let x509_chain = X509CertificateIter::from(
            chain
                .iter()
                .map(AsRef::<[u8]>::as_ref)
                .collect::<Vec<&[u8]>>(),
        )
        .collect::<Vec<X509Certificate>>();
        let _length = x509_chain.verify_chain()?;

        // Make sure the last verified cert in the chain uses the privkey we loaded
        // separately
        let chain_pubkey =
            Ed25519Public::try_from_der(x509_chain.leaf()?.subject_public_key_info().spki())?;
        if signing_keypair.public_key() != chain_pubkey {
            return Err(Error::ChainKeyMismatch);
        }

        Ok(Materials {
            chain,
            signing_keypair,
        })
    }
}

impl Clone for Materials {
    fn clone(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            signing_keypair: self.signing_keypair.private_key().into(),
        }
    }
}

impl TryFrom<&Config> for Materials {
    type Error = Error;

    /// Try and load items specified in the configuration file into usable
    /// cryptographic materials
    fn try_from(src: &Config) -> Result<Self> {
        Self::from_pems(
            fs::read_to_string(&src.signing_chain)?,
            fs::read_to_string(&src.signing_key)?,
        )
    }
}
