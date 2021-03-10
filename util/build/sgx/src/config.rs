// Copyright (c) 2018-2021 The MobileCoin Foundation

//! SGX Config XML Builder

use std::{
    convert::TryInto,
    fmt::{Display, Formatter, Result as FmtResult},
    fs::File,
    io::Write,
    path::Path,
};

/// An enumeration of TCS policy options.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TcsPolicy {
    /// Thread control structures are bound to untrusted threads
    Bound = 0,
    /// Thread control structures are not bound to untrusted threads
    Unbound = 1,
}

impl Default for TcsPolicy {
    fn default() -> Self {
        TcsPolicy::Unbound
    }
}

/// This builder creates the Enclave.config.xml config file used by sgx_sign.
///
/// See "Intel SGX Developer Reference" section "Enclave Configuration File" for
/// more information on what the methods are setting.
#[derive(Clone, Debug, Default)]
pub struct ConfigBuilder {
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
    reserved_mem_max_size: Option<usize>,
    reserved_mem_min_size: Option<usize>,
    reserved_mem_init_size: Option<usize>,
    reserved_memory_executable: Option<bool>,
    disable_debug: Option<bool>,
    misc_select: Option<u32>,
    misc_mask: Option<u32>,
    enable_kss: Option<bool>,
    isv_ext_prod_id_high: Option<u64>,
    isv_ext_prod_id_low: Option<u64>,
    isv_family_id_high: Option<u64>,
    isv_family_id_low: Option<u64>,
}

impl ConfigBuilder {
    /// ISV assigned product ID (default: 0).
    pub fn prod_id(&mut self, prod_id: u16) -> &mut Self {
        self.prod_id = Some(prod_id);
        self
    }

    /// ISV assigned security version (default: 0).
    pub fn isv_security_version(&mut self, isv_svn: u16) -> &mut Self {
        self.isv_security_version = Some(isv_svn);
        self
    }

    /// The number of thread control structures (default: 1).
    pub fn tcs_num(&mut self, num: usize) -> &mut Self {
        self.tcs_num = Some(num);
        self
    }

    /// The maximum number of thread control structures (default: 1).
    pub fn tcs_max_num(&mut self, max_num: usize) -> &mut Self {
        self.tcs_max_num = Some(max_num);
        self
    }

    /// The minimum number of available thread control structures at any time in
    /// the life cycle of an enclave (default: 1).
    pub fn tcs_min_pool(&mut self, min_pool: usize) -> &mut Self {
        self.tcs_min_pool = Some(min_pool);
        self
    }

    /// TCS management policy.
    pub fn tcs_policy(&mut self, policy: TcsPolicy) -> &mut Self {
        self.tcs_policy = Some(policy);
        self
    }

    /// The minimum stack size per thread, must be 4KiB-aligned (default: 8KiB).
    pub fn stack_min_size(&mut self, min_size: usize) -> &mut Self {
        self.stack_min_size = Some(min_size);
        self
    }

    /// The maximum stack size per thread, must be 4KiB-aligned (default:
    /// 256KiB).
    pub fn stack_max_size(&mut self, max_size: usize) -> &mut Self {
        self.stack_max_size = Some(max_size);
        self
    }

    /// The initial heap size for the process, must be 4KiB-aligned (default:
    /// 16MiB).
    pub fn heap_init_size(&mut self, init_size: usize) -> &mut Self {
        self.heap_init_size = Some(init_size);
        self
    }

    /// The minimum heap size for the process, must be 4KiB-aligned (default:
    /// 4KiB).
    pub fn heap_min_size(&mut self, min_size: usize) -> &mut Self {
        self.heap_min_size = Some(min_size);
        self
    }

    /// The maximum heap size for the process, must be 4KiB-aligned (default:
    /// 16MiB).
    pub fn heap_max_size(&mut self, max_size: usize) -> &mut Self {
        self.heap_max_size = Some(max_size);
        self
    }

    /// The maximum reserved memory for the process, must be 4KiB-aligned
    /// (default: 0).
    pub fn reserved_mem_max_size(&mut self, max_size: usize) -> &mut Self {
        self.reserved_mem_max_size = Some(max_size);
        self
    }

    /// The minimum reserved memory for the process, must be 4KiB-aligned
    /// (default: 0).
    pub fn reserved_mem_min_size(&mut self, min_size: usize) -> &mut Self {
        self.reserved_mem_min_size = Some(min_size);
        self
    }

    /// The initial reserved memory size for the process, must be 4KiB-aligned
    /// (default: 0).
    pub fn reserved_mem_init_size(&mut self, init_size: usize) -> &mut Self {
        self.reserved_mem_init_size = Some(init_size);
        self
    }

    /// The reserved memory is executable (only used for SGX 1 platform,
    /// default: false).
    pub fn reserved_memory_executable(&mut self, exec: bool) -> &mut Self {
        self.reserved_memory_executable = Some(exec);
        self
    }

    /// Enclave can/cannot be debugged.
    pub fn debug(&mut self, use_debug: bool) -> &mut Self {
        self.disable_debug = Some(!use_debug);
        self
    }

    /// The desired extended SSA frame feature and it's mask.
    pub fn misc_select(&mut self, misc_select: u32, misc_mask: u32) -> &mut Self {
        self.misc_select = Some(misc_select);
        self.misc_mask = Some(misc_mask);
        self
    }

    /// Enable the Key Separation and Sharing feature,
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
            File::create(config_path).expect("Could not create/truncate XML config file");
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

impl Display for ConfigBuilder {
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
            f, self.reserved_mem_max_size, hexnum, "ReservedMemMaxSize";
            f, self.reserved_mem_min_size, hexnum, "ReservedMemMinSize";
            f, self.reserved_mem_init_size, hexnum, "ReservedMemInitSize";
            f, self.reserved_memory_executable,  asu8, "ReservedMemoryExecutable";
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
