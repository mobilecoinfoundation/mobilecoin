// Copyright (c) 2018-2021 The MobileCoin Foundation

//! Builder for signing an enclave using the sgx_sign binary application

use std::{
    convert::TryInto,
    env::var,
    fmt::{Display, Formatter, Result as FmtResult},
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
};

#[repr(u8)]
#[derive(Copy, Clone, Debug)]
pub enum TcsPolicy {
    Bound = 0,
    Unbound = 1,
}

impl Default for TcsPolicy {
    fn default() -> Self {
        TcsPolicy::Unbound
    }
}

/// This builder creates the Enclave.config.xml config file used by sgx_sign.
///
/// See "Intel SGX Developer Reference" section "Enclave Configuration File" for more information.
#[derive(Clone, Debug, Default)]
pub struct SgxConfigBuilder {
    prod_id: Option<u16>,
    isv_security_version: Option<u16>,
    stack_min_size: Option<usize>,
    stack_max_size: Option<usize>,
    heap_init_size: Option<usize>,
    heap_min_size: Option<usize>,
    heap_max_size: Option<usize>,
    tcs_num: Option<usize>,
    tcs_max_num: Option<usize>,
    tcs_min_pool: Option<usize>,
    tcs_policy: Option<TcsPolicy>,
    disable_debug: Option<bool>,
    misc_select: Option<u32>,
    misc_mask: Option<u32>,
    enable_kss: Option<bool>,
    isv_ext_prod_id_high: Option<u64>,
    isv_ext_prod_id_low: Option<u64>,
    isv_family_id_high: Option<u64>,
    isv_family_id_low: Option<u64>,
}

impl SgxConfigBuilder {
    pub fn prod_id(&mut self, prod_id: u16) -> &mut Self {
        self.prod_id = Some(prod_id);
        self
    }

    pub fn isv_security_version(&mut self, isv_svn: u16) -> &mut Self {
        self.isv_security_version = Some(isv_svn);
        self
    }

    pub fn tcs_num(&mut self, num: usize) -> &mut Self {
        self.tcs_num = Some(num);
        self
    }

    pub fn tcs_max_num(&mut self, max_num: usize) -> &mut Self {
        self.tcs_max_num = Some(max_num);
        self
    }

    pub fn tcs_min_pool(&mut self, min_pool: usize) -> &mut Self {
        self.tcs_min_pool = Some(min_pool);
        self
    }

    pub fn tcs_policy(&mut self, policy: TcsPolicy) -> &mut Self {
        self.tcs_policy = Some(policy);
        self
    }

    pub fn stack_min_size(&mut self, min_size: usize) -> &mut Self {
        self.stack_min_size = Some(min_size);
        self
    }

    pub fn stack_max_size(&mut self, max_size: usize) -> &mut Self {
        self.stack_max_size = Some(max_size);
        self
    }

    pub fn heap_init_size(&mut self, init_size: usize) -> &mut Self {
        self.heap_init_size = Some(init_size);
        self
    }

    pub fn heap_min_size(&mut self, min_size: usize) -> &mut Self {
        self.heap_min_size = Some(min_size);
        self
    }

    pub fn heap_max_size(&mut self, max_size: usize) -> &mut Self {
        self.heap_max_size = Some(max_size);
        self
    }

    pub fn debug(&mut self, use_debug: bool) -> &mut Self {
        self.disable_debug = Some(!use_debug);
        self
    }

    pub fn misc_select(&mut self, misc_select: u32, misc_mask: u32) -> &mut Self {
        self.misc_select = Some(misc_select);
        self.misc_mask = Some(misc_mask);
        self
    }

    pub fn enable_kss(&mut self, isv_extended_product_id: u128, isv_family_id: u128) -> &mut Self {
        // All these should be infallible.
        self.isv_ext_prod_id_high = Some((isv_extended_product_id >> 64).try_into().unwrap());
        self.isv_ext_prod_id_low = Some(
            (isv_extended_product_id & 0x0000_0000_0000_0000_ffff_ffff_ffff_ffff)
                .try_into()
                .unwrap(),
        );
        self.isv_family_id_high = Some((isv_family_id >> 64).try_into().unwrap());
        self.isv_family_id_low = Some(
            (isv_family_id & 0x0000_0000_0000_0000_ffff_ffff_ffff_ffff)
                .try_into()
                .unwrap(),
        );
        self.enable_kss = Some(true);
        self
    }

    /// Write the configuration file and return its path.
    pub fn write_to_file(&self, config_path: &Path) {
        let mut config_file =
            File::create(config_path).expect("Could not create/truncate config file");
        write!(config_file, "{}", &self).expect("Could not output string for SgxConfigBuilder");
    }
}

macro_rules! write_one_config_xml {
    ($config_file:expr, $member:expr, simple, $tag:literal) => {
        if let Some(value) = &$member {
            write!($config_file, "<{}>{}</{}>", $tag, value, $tag)?;
        }
    };
    ($config_file:expr, $member:expr, hexnum, $tag:literal) => {
        if let Some(value) = &$member {
            write!($config_file, "<{}>0x{:x}</{}>", $tag, value, $tag)?;
        }
    };
    ($config_file:expr, $member:expr, asu8, $tag:literal) => {
        if let Some(value) = &$member {
            write!($config_file, "<{}>{}</{}>", $tag, *value as u8, $tag)?;
        }
    };
    ($config_file:expr, $member:expr, zerohex32, $tag:literal) => {
        if let Some(value) = &$member {
            write!($config_file, "<{}>0x{:08x}</{}>", $tag, value, $tag)?;
        }
    };
}

macro_rules! write_config_xml {
    ($($config_file:expr, $member:expr, $typestring:ident, $tag:literal;)*) => {$(
        write_one_config_xml! {$config_file, $member, $typestring, $tag }
    )*};
}

impl Display for SgxConfigBuilder {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "<EnclaveConfiguration>")?;
        write_config_xml! {
            f, self.prod_id, simple, "ProdID";
            f, self.isv_security_version, simple, "ISVSVN";
            f, self.stack_min_size, hexnum, "StackMinSize";
            f, self.stack_max_size, hexnum, "StackMaxSize";
            f, self.heap_init_size, hexnum, "HeapInitSize";
            f, self.heap_min_size, hexnum, "HeapMinSize";
            f, self.heap_max_size, hexnum, "HeapMaxSize";
            f, self.tcs_num, simple, "TCSNum";
            f, self.tcs_max_num, simple, "TCSMaxNum";
            f, self.tcs_min_pool, simple, "TCSMinPool";
            f, self.tcs_policy, asu8, "TCSPolicy";
            f, self.disable_debug, asu8, "DisableDebug";
            f, self.misc_select, simple, "MiscSelect";
            f, self.misc_mask, zerohex32, "MiscMask";
            f, self.enable_kss, asu8, "EnableKSS";
            f, self.isv_ext_prod_id_high, simple, "ISVEXTPRODID_H";
            f, self.isv_ext_prod_id_low, simple, "ISVEXTPRODID_L";
            f, self.isv_family_id_high, simple, "ISVFAMILYID_H";
            f, self.isv_family_id_low, simple, "ISVFAMILYID_L";
        }
        write!(f, "</EnclaveConfiguration>")
    }
}

/// This structure wraps the execution of sgx_sign commands.
pub struct SgxSign {
    /// The path to the sgx_sign executable.
    sgx_sign_path: PathBuf,

    /// Whether to ignore the presence of relocations in the enclave shared object.
    ignore_rel_error: bool,
    /// Whether to ignore .init sections in the enclave.
    ignore_init_sec_error: bool,
    /// Whether to re-sign a previously signed enclave (default: false)
    resign: bool,
}

impl SgxSign {
    pub fn allow_relocations(mut self, allow: bool) -> Self {
        self.ignore_rel_error = allow;
        self
    }

    pub fn allow_init_sections(mut self, allow: bool) -> Self {
        self.ignore_init_sec_error = allow;
        self
    }

    pub fn allow_resign(mut self, allow: bool) -> Self {
        self.resign = allow;
        self
    }

    /// Sign the given enclave object with the given private key and write the resulting enclave to
    /// the given path. Note that online signatures are inherently insecure.
    pub fn sign(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        private_key: &Path,
        output_enclave: &Path,
    ) -> &mut Self {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        let cmd = cmd
            .arg("sign")
            .arg("-enclave")
            .arg(unsigned_enclave)
            .arg("-config")
            .arg(&config_path)
            .arg("-key")
            .arg(private_key)
            .arg("-out")
            .arg(output_enclave);

        let cmd = if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error")
        } else {
            cmd
        };

        let cmd = if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error")
        } else {
            cmd
        };

        let cmd = if self.resign { cmd.arg("-resign") } else { cmd };

        assert!(
            cmd.status().expect("Could not execute sgx_sign").success(),
            "sgx_sign failed"
        );
        self
    }

    /// Generate the data required for offline signing, and write it to the given output data path.
    pub fn gendata(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        output_datfile: &Path,
    ) -> &mut Self {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        let cmd = cmd
            .arg("gendata")
            .arg("-enclave")
            .arg(unsigned_enclave)
            .arg("-config")
            .arg(&config_path)
            .arg("-out")
            .arg(output_datfile);

        let cmd = if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error")
        } else {
            cmd
        };

        let cmd = if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error")
        } else {
            cmd
        };

        let cmd = if self.resign { cmd.arg("-resign") } else { cmd };

        assert!(
            cmd.status().expect("Could not execute sgx_sign").success(),
            "sgx_sign failed"
        );
        self
    }

    /// Combine an unsigned enclave and signature into the output enclave, after checking the
    /// signature.
    pub fn catsig(
        &mut self,
        unsigned_enclave: &Path,
        config_path: &Path,
        public_key_pem: &Path,
        gendata_output: &Path,
        signature: &Path,
        output_enclave: &Path,
    ) -> &mut Self {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        let cmd = cmd
            .arg("catsig")
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

        let cmd = if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error")
        } else {
            cmd
        };

        let cmd = if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error")
        } else {
            cmd
        };

        let cmd = if self.resign { cmd.arg("-resign") } else { cmd };

        assert!(
            cmd.status().expect("Could not execute sgx_sign").success(),
            "sgx_sign failed"
        );
        self
    }

    /// Examine a signed enclave file and dump the data
    pub fn dump(
        &mut self,
        signed_enclave: &Path,
        css_file_path: &Path,
        dump_file_path: &Path,
    ) -> &mut Self {
        let mut cmd = Command::new(self.sgx_sign_path.clone());
        let cmd = cmd
            .arg("dump")
            .arg("-enclave")
            .arg(signed_enclave)
            .arg("-dumpfile")
            .arg(dump_file_path)
            .arg("-cssfile")
            .arg(css_file_path);

        let cmd = if self.ignore_rel_error {
            cmd.arg("-ignore-rel-error")
        } else {
            cmd
        };

        let cmd = if self.ignore_init_sec_error {
            cmd.arg("-ignore-init-sec-error")
        } else {
            cmd
        };

        let cmd = if self.resign { cmd.arg("-resign") } else { cmd };

        assert!(
            cmd.status().expect("Could not execute sgx_sign").success(),
            "sgx_sign failed"
        );
        self
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

/// Construct an SgxSign utility, using $SGX_SDK/bin/x64/sgx_sign or /opt/intel/sgxsdk/bin/sgx_sign
/// (if SGX_SDK is not defind) as the executable.
impl Default for SgxSign {
    fn default() -> Self {
        let mut sgx_sign_path =
            PathBuf::from(var("SGX_SDK").unwrap_or_else(|_| String::from("/opt/intel/sgxsdk")));
        sgx_sign_path.push("bin");
        sgx_sign_path.push("x64");
        sgx_sign_path.push("sgx_sign");
        Self::from(sgx_sign_path)
    }
}
