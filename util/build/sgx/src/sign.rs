// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Builder wrapper around SgxSign.

use crate::utils::get_binary;
use pkg_config::Error as PkgConfigError;
use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// This structure wraps the execution of sgx_sign commands.
#[derive(Clone, Debug)]
pub struct SgxSign {
    /// The path to the sgx_sign executable.
    sgx_sign_path: PathBuf,
    /// Whether to ignore the presence of relocations in the enclave shared
    /// object.
    ignore_rel_error: bool,
    /// Whether to ignore .init sections in the enclave.
    ignore_init_sec_error: bool,
    /// Whether to re-sign a previously signed enclave (default: false)
    resign: bool,
}

impl SgxSign {
    /// Create a new SGX signing utility from the current environment.
    pub fn new(target_arch: &str) -> Result<Self, PkgConfigError> {
        get_binary(target_arch, "sgx_sign").map(Self::from)
    }

    /// Relocations are generally forbidden in the enclave shared object, this
    /// tells the `sgx_sign` utility to ignore those errors.
    pub fn allow_relocations(mut self, allow: bool) -> Self {
        self.ignore_rel_error = allow;
        self
    }

    /// Whether or not to allow .init sections in the enclave.
    pub fn allow_init_sections(mut self, allow: bool) -> Self {
        self.ignore_init_sec_error = allow;
        self
    }

    /// Whether to re-sign a previously signed enclave (default: false)
    pub fn allow_resign(mut self, allow: bool) -> Self {
        self.resign = allow;
        self
    }

    /// Generate the command to sign the given enclave object with the given
    /// private key and write the resulting enclave to the given path. Note
    /// that online signatures are inherently insecure.
    pub fn sign(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        private_key: &Path,
        output_enclave: &Path,
    ) -> Command {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        cmd.arg("sign")
            .arg("-enclave")
            .arg(unsigned_enclave)
            .arg("-config")
            .arg(&config_path)
            .arg("-key")
            .arg(private_key)
            .arg("-out")
            .arg(output_enclave);

        if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }

    /// Generate the command to create the data required for offline signing,
    /// and write it to the given output data path.
    pub fn gendata(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        output_datfile: &Path,
    ) -> Command {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        cmd.arg("gendata")
            .arg("-enclave")
            .arg(unsigned_enclave)
            .arg("-config")
            .arg(&config_path)
            .arg("-out")
            .arg(output_datfile);

        if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }

    /// Combine an unsigned enclave and signature into the output enclave, after
    /// checking the signature.
    pub fn catsig(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        public_key_pem: &Path,
        gendata_output: &Path,
        signature: &Path,
        output_enclave: &Path,
    ) -> Command {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        cmd.arg("catsig")
            .arg("-enclave")
            .arg(&unsigned_enclave)
            .arg("-config")
            .arg(&config_path)
            .arg("-key")
            .arg(&public_key_pem)
            .arg("-unsigned")
            .arg(&gendata_output)
            .arg("-sig")
            .arg(&signature)
            .arg("-out")
            .arg(&output_enclave);

        if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error");
        }

        cmd
    }

    /// Examine a signed enclave file and dump the data
    pub fn dump(
        &mut self,
        signed_enclave: &Path,
        css_file_path: &Path,
        dump_file_path: &Path,
    ) -> Command {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        cmd.arg("dump")
            .arg("-enclave")
            .arg(signed_enclave)
            .arg("-dumpfile")
            .arg(dump_file_path)
            .arg("-cssfile")
            .arg(css_file_path);

        if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }
}

/// Construct a new SgxSign utility around the given executable path
impl From<PathBuf> for SgxSign {
    fn from(sgx_sign_path: PathBuf) -> Self {
        Self {
            sgx_sign_path,
            ignore_rel_error: false,
            ignore_init_sec_error: false,
            resign: false,
        }
    }
}
