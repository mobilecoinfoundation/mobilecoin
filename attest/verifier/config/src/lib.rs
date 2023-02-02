// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This crate provides a `load_attestation_trust_roots_for_enclave` function
//! which searches a search path for attestation trust roots corresponding to
//! an enclave of a given name, then configures an attestation verifier to trust
//! all matching trust roots.

#![deny(missing_docs)]

use displaydoc::Display;
use mc_attest_verifier::{MrEnclaveVerifier, MrSignerVerifier, Verifier};
use mc_common::logger::{log, Logger};
use mc_sgx_css::{Error as CssError, Signature};
use serde::{Deserialize, Serialize};
use serde_json::Error as SerdeJsonError;
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

/// Load attestation trust roots from the filesystem for a particular enclave.
///
/// The search path is expected to contain subdirectories, each corresponding to
/// a release. Each subdirectory is searched for files matching
/// "{enclave_name}.css" and "{enclave_name}.json". If one is present but not
/// the other, this is an error. When both are present, a corresponding
/// StatusVerifier is created and appended to the verifier.
///
/// Arguments:
/// * enclave_name: The name of the enclave that we are creating a verifier for
/// * search_path: The directory to search for trust roots
/// * verifier: The verifier object to which we will append our findings
/// * logger
///
/// Returns:
/// A count of the number of trust roots loaded for this enclave, or an error.
/// If an error occurs the verifier should be abandoned.
pub fn load_attestation_trust_roots_for_enclave(
    enclave_name: &'static str,
    search_path: impl AsRef<Path>,
    verifier: &mut Verifier,
    logger: &Logger,
) -> Result<usize, Error> {
    let mut count = 0;

    log::debug!(
        logger,
        "Searching for attestation trust roots for '{}' in: {}",
        enclave_name,
        search_path.as_ref().display()
    );

    let search_path = search_path.as_ref();
    if !search_path.is_dir() {
        return Err(Error::NotADirectory(search_path.to_path_buf()));
    }

    for entry in
        fs::read_dir(search_path).map_err(|err| Error::Io(search_path.to_path_buf(), err))?
    {
        let entry = entry.map_err(|err| Error::Io(search_path.to_path_buf(), err))?;
        let path = entry.path();
        if path.file_name() == Some(OsStr::new(".")) || path.file_name() == Some(OsStr::new("..")) {
            continue;
        }

        if !path.is_dir() {
            continue;
        }

        log::debug!(logger, "Searching in subdirectory: {}", path.display());

        // Add a path element corresponding to enclave_name, and see if we find css and
        // json files for this
        let css_path = path.join(enclave_name).with_extension("css");
        let json_path = path.join(enclave_name).with_extension("json");

        if css_path.is_file() && json_path.is_file() {
            // TODO: Check if both files are readonly?

            let signature = {
                let bytes = fs::read(&css_path).map_err(|err| Error::Io(css_path.clone(), err))?;
                Signature::try_from(&bytes[..])
                    .map_err(|err| Error::Signature(css_path.clone(), err))?
            };

            let json: AttestConfigJson = {
                let bytes =
                    fs::read(&json_path).map_err(|err| Error::Io(json_path.clone(), err))?;
                serde_json::from_slice(&bytes[..])
                    .map_err(|err| Error::Json(json_path.clone(), err))?
            };

            log::debug!(
                logger,
                "Found attestation trust root: {}, {}",
                css_path.display(),
                json_path.display()
            );

            let hardening_advisories: Vec<&str> = json
                .mitigated_hardening_advisories
                .iter()
                .map(|x| x.as_str())
                .collect();

            match json.identity_check {
                IdentityCheck::Mrenclave => {
                    let mut mr_enclave_verifier = MrEnclaveVerifier::from(signature);
                    mr_enclave_verifier.allow_hardening_advisories(&hardening_advisories);
                    verifier.mr_enclave(mr_enclave_verifier);
                }
                IdentityCheck::Mrsigner => {
                    let mut mr_signer_verifier = MrSignerVerifier::from(signature);
                    mr_signer_verifier.allow_hardening_advisories(&hardening_advisories);
                    verifier.mr_signer(mr_signer_verifier);
                }
            };

            count += 1;
        } else if css_path.is_file() {
            return Err(Error::CssWithoutMatchingJson(css_path));
        } else if json_path.is_file() {
            return Err(Error::JsonWithoutMatchingCss(json_path));
        }
    }

    Ok(count)
}

/// An error which can occur when trying to load attestation trust roots from a
/// search path
#[derive(Display, Debug)]
pub enum Error {
    /// Io: {0:?}
    Io(PathBuf, std::io::Error),

    /// Error reading css signature file {0:?}: {1}
    Signature(PathBuf, CssError),

    /// Error reading json file {0:?}: {1}
    Json(PathBuf, SerdeJsonError),

    /// .css file without matching json: {0:?}
    CssWithoutMatchingJson(PathBuf),

    /// .json file without matching css: {0:?}
    JsonWithoutMatchingCss(PathBuf),

    /// Search path was not a directory: {0:?}
    NotADirectory(PathBuf),
}

/// The schema of a json file which lives adjacent to a .css sigstruct file,
/// and informs how to configure the associated status verifier.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AttestConfigJson {
    /// Whether we are checking the enclave identity or the signer identity
    pub identity_check: IdentityCheck,
    /// What hardening advisories are known to be mitigated for this enclave
    pub mitigated_hardening_advisories: Vec<String>,
}

/// The possibilities for the `identity_check` field in the AttestConfigJson
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IdentityCheck {
    /// Indicates to use MRENCLAVE verification
    Mrenclave,
    /// Indicates to use MRSIGNER verification
    Mrsigner,
}
