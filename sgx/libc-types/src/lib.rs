// Copyright (c) 2018-2020 MobileCoin Inc.

#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

pub use core::ffi::c_void;
pub type c_char = i8; // char is signed on x86 gcc and clang
pub type c_int = i32;
pub type uintptr_t = usize;
pub type int32_t = i32;

/// libc error symbols (these values from rust-sgx-sdk)

pub const EPERM: int32_t = 1;
pub const ENOENT: int32_t = 2;
pub const ESRCH: int32_t = 3;
pub const EINTR: int32_t = 4;
pub const EIO: int32_t = 5;
pub const ENXIO: int32_t = 6;
pub const E2BIG: int32_t = 7;
pub const ENOEXEC: int32_t = 8;
pub const EBADF: int32_t = 9;
pub const ECHILD: int32_t = 10;
pub const EAGAIN: int32_t = 11;
pub const ENOMEM: int32_t = 12;
pub const EACCES: int32_t = 13;
pub const EFAULT: int32_t = 14;
pub const ENOTBLK: int32_t = 15;
pub const EBUSY: int32_t = 16;
pub const EEXIST: int32_t = 17;
pub const EXDEV: int32_t = 18;
pub const ENODEV: int32_t = 19;
pub const ENOTDIR: int32_t = 20;
pub const EISDIR: int32_t = 21;
pub const EINVAL: int32_t = 22;
pub const ENFILE: int32_t = 23;
pub const EMFILE: int32_t = 24;
pub const ENOTTY: int32_t = 25;
pub const ETXTBSY: int32_t = 26;
pub const EFBIG: int32_t = 27;
pub const ENOSPC: int32_t = 28;
pub const ESPIPE: int32_t = 29;
pub const EROFS: int32_t = 30;
pub const EMLINK: int32_t = 31;
pub const EPIPE: int32_t = 32;
pub const EDOM: int32_t = 33;
pub const ERANGE: int32_t = 34;
pub const EDEADLK: int32_t = 35;
pub const ENAMETOOLONG: int32_t = 36;
pub const ENOLCK: int32_t = 37;
pub const ENOSYS: int32_t = 38;
pub const ENOTEMPTY: int32_t = 39;
pub const ELOOP: int32_t = 40;
pub const EWOULDBLOCK: int32_t = EAGAIN;
pub const ENOMSG: int32_t = 42;
pub const EIDRM: int32_t = 43;
pub const ECHRNG: int32_t = 44;
pub const EL2NSYNC: int32_t = 45;
pub const EL3HLT: int32_t = 46;
pub const EL3RST: int32_t = 47;
pub const ELNRNG: int32_t = 48;
pub const EUNATCH: int32_t = 49;
pub const ENOCSI: int32_t = 50;
pub const EL2HLT: int32_t = 51;
pub const EBADE: int32_t = 52;
pub const EBADR: int32_t = 53;
pub const EXFULL: int32_t = 54;
pub const ENOANO: int32_t = 55;
pub const EBADRQC: int32_t = 56;
pub const EBADSLT: int32_t = 57;
pub const EDEADLOCK: int32_t = EDEADLK;
pub const EBFONT: int32_t = 59;
pub const ENOSTR: int32_t = 60;
pub const ENODATA: int32_t = 61;
pub const ETIME: int32_t = 62;
pub const ENOSR: int32_t = 63;
pub const ENONET: int32_t = 64;
pub const ENOPKG: int32_t = 65;
pub const EREMOTE: int32_t = 66;
pub const ENOLINK: int32_t = 67;
pub const EADV: int32_t = 68;
pub const ESRMNT: int32_t = 69;
pub const ECOMM: int32_t = 70;
pub const EPROTO: int32_t = 71;
pub const EMULTIHOP: int32_t = 72;
pub const EDOTDOT: int32_t = 73;
pub const EBADMSG: int32_t = 74;
pub const EOVERFLOW: int32_t = 75;
pub const ENOTUNIQ: int32_t = 76;
pub const EBADFD: int32_t = 77;
pub const EREMCHG: int32_t = 78;
pub const ELIBACC: int32_t = 79;
pub const ELIBBAD: int32_t = 80;
pub const ELIBSCN: int32_t = 81;
pub const ELIBMAX: int32_t = 82;
pub const ELIBEXEC: int32_t = 83;
pub const EILSEQ: int32_t = 84;
pub const ERESTART: int32_t = 85;
pub const ESTRPIPE: int32_t = 86;
pub const EUSERS: int32_t = 87;
pub const ENOTSOCK: int32_t = 88;
pub const EDESTADDRREQ: int32_t = 89;
pub const EMSGSIZE: int32_t = 90;
pub const EPROTOTYPE: int32_t = 91;
pub const ENOPROTOOPT: int32_t = 92;
pub const EPROTONOSUPPORT: int32_t = 93;
pub const ESOCKTNOSUPPORT: int32_t = 94;
pub const EOPNOTSUPP: int32_t = 95;
pub const EPFNOSUPPORT: int32_t = 96;
pub const EAFNOSUPPORT: int32_t = 97;
pub const EADDRINUSE: int32_t = 98;
pub const EADDRNOTAVAIL: int32_t = 99;
pub const ENETDOWN: int32_t = 100;
pub const ENETUNREACH: int32_t = 101;
pub const ENETRESET: int32_t = 102;
pub const ECONNABORTED: int32_t = 103;
pub const ECONNRESET: int32_t = 104;
pub const ENOBUFS: int32_t = 105;
pub const EISCONN: int32_t = 106;
pub const ENOTCONN: int32_t = 107;
pub const ESHUTDOWN: int32_t = 108;
pub const ETOOMANYREFS: int32_t = 109;
pub const ETIMEDOUT: int32_t = 110;
pub const ECONNREFUSED: int32_t = 111;
pub const EHOSTDOWN: int32_t = 112;
pub const EHOSTUNREACH: int32_t = 113;
pub const EALREADY: int32_t = 114;
pub const EINPROGRESS: int32_t = 115;
pub const ESTALE: int32_t = 116;
pub const EUCLEAN: int32_t = 117;
pub const ENOTNAM: int32_t = 118;
pub const ENAVAIL: int32_t = 119;
pub const EISNAM: int32_t = 120;
pub const EREMOTEIO: int32_t = 121;
pub const EDQUOT: int32_t = 122;
pub const ENOMEDIUM: int32_t = 123;
pub const EMEDIUMTYPE: int32_t = 124;
pub const ECANCELED: int32_t = 125;
pub const ENOKEY: int32_t = 126;
pub const EKEYEXPIRED: int32_t = 127;
pub const EKEYREVOKED: int32_t = 128;
pub const EKEYREJECTED: int32_t = 129;
pub const EOWNERDEAD: int32_t = 130;
pub const ENOTRECOVERABLE: int32_t = 131;
pub const ERFKILL: int32_t = 132;
pub const EHWPOISON: int32_t = 133;
pub const ENOTSUP: int32_t = EOPNOTSUPP;
pub const ESGX: int32_t = 0x0000_FFFF;

/// Other ffi types

/// Represents an item in the backtrace list. See `unwind_backtrace` for how
/// it is created.
///
/// Note(chris): In rust std this appears in `sys_common/backtrace.rs`
/// Note(chris): Our version is additionally repr(C) because it is passed across
/// enclave OCALL boundary. This must be kept in sync wtih the edl file.
///
#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct Frame {
    /// Exact address of the call that failed.
    pub exact_position: *const u8,
    /// Address of the enclosing function.
    pub symbol_addr: *const u8,
    /// Which inlined function is this frame referring to
    pub inline_context: u32,
}
