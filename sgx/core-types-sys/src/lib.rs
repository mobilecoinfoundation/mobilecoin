// Copyright (c) 2018-2020 MobileCoin Inc.

//! Intel SGX SDK Core FFI Types

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::missing_safety_doc)]
#![allow(clippy::useless_transmute)]

/// This is copy-pasted from std::os::raw as of nightly-2019-12-19
pub mod ctypes {
    #[cfg(any(
        all(
            target_os = "linux",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "hexagon",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "s390x"
            )
        ),
        all(
            target_os = "android",
            any(target_arch = "aarch64", target_arch = "arm")
        ),
        all(target_os = "l4re", target_arch = "x86_64"),
        all(
            target_os = "freebsd",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        ),
        all(
            target_os = "netbsd",
            any(target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc")
        ),
        all(target_os = "openbsd", target_arch = "aarch64"),
        all(
            target_os = "vxworks",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc64",
                target_arch = "powerpc"
            )
        ),
        all(target_os = "fuchsia", target_arch = "aarch64")
    ))]
    pub type c_char = u8;
    #[cfg(not(any(
        all(
            target_os = "linux",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "hexagon",
                target_arch = "powerpc",
                target_arch = "powerpc64",
                target_arch = "s390x"
            )
        ),
        all(
            target_os = "android",
            any(target_arch = "aarch64", target_arch = "arm")
        ),
        all(target_os = "l4re", target_arch = "x86_64"),
        all(
            target_os = "freebsd",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc",
                target_arch = "powerpc64"
            )
        ),
        all(
            target_os = "netbsd",
            any(target_arch = "aarch64", target_arch = "arm", target_arch = "powerpc")
        ),
        all(target_os = "openbsd", target_arch = "aarch64"),
        all(
            target_os = "vxworks",
            any(
                target_arch = "aarch64",
                target_arch = "arm",
                target_arch = "powerpc64",
                target_arch = "powerpc"
            )
        ),
        all(target_os = "fuchsia", target_arch = "aarch64")
    )))]
    pub type c_char = i8;
    pub type c_schar = i8;
    pub type c_uchar = u8;
    pub type c_short = i16;
    pub type c_ushort = u16;
    pub type c_int = i32;
    pub type c_uint = u32;
    #[cfg(any(target_pointer_width = "32", windows))]
    pub type c_long = i32;
    #[cfg(any(target_pointer_width = "32", windows))]
    pub type c_ulong = u32;
    #[cfg(all(target_pointer_width = "64", not(windows)))]
    pub type c_long = i64;
    #[cfg(all(target_pointer_width = "64", not(windows)))]
    pub type c_ulong = u64;
    pub type c_longlong = i64;
    pub type c_ulonglong = u64;
    pub type c_float = f32;
    pub type c_double = f64;
    pub use core::ffi::c_void;
}

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
